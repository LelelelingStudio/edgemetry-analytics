import { type Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';

import {
  SESSION_COOKIE,
  SETTING_SESSION_SECRET,
  issueSession,
  randomHex,
  readSession,
  sessionCookieOptions,
} from './auth';
import dashboardTemplate from './dashboard.html';
import gamecheckPage from '../gamecheck.html';
import { ensureSchema, getSetting, setSetting } from './db';
import { FONT_FACE_CSS, FONT_FILES } from './fonts';
import { isBreakdownDim } from './dimensions';
import { FAVICON_SVG } from './favicon';
import { corsPreflight, handleIngest } from './ingest';
import { loginPage, setupPage } from './pages';
import {
  METRICS,
  type Components,
  type Metric,
  loadBreakdowns,
  loadRealtime,
  loadSeries,
  metricValue,
  parseFilters,
  resolveRange,
  totalsFrom,
} from './query';
import { catchUpToday, dailyJob, hourlyJob } from './rollup';
import { getStats } from './stats';
import { dayOffset, isValidDay, partsFor } from './time';
import { trackerResponse } from './tracker';
import { checkForUpdate, readUpdateStatus } from './update';
import { VERSION } from './version';
import { WORLD_GEOMETRY } from './world';
import {
  MIN_PASSWORD_LENGTH,
  type Role,
  type UserRow,
  accessibleSites,
  canAccessSite,
  countOwners,
  countUsers,
  createFirstOwner,
  createUser,
  deleteUser,
  getUserByEmail,
  getUserById,
  isOwner,
  isValidEmail,
  listUsers,
  normalizeEmail,
  setPassword,
  setRole,
  setSiteAccess,
  siteIdsFor,
  toPublicUser,
  verifyPassword,
} from './users';

/**
 * Paths the Worker owns. Everything else is fair game for the tracker script
 * and its matching ingest endpoint, which is what lets each deployment choose
 * its own unguessable path.
 */
const RESERVED_PATHS = new Set([
  'api',
  'setup',
  'login',
  'logout',
  'health',
  'robots.txt',
  'favicon.ico',
  'favicon.svg',
]);

const DOMAIN_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const CORS_ALLOW_ORIGIN = 'https://game.leleleling.site';
const CORS_ALLOW_METHODS = 'GET, POST, OPTIONS';
const CORS_ALLOW_HEADERS = 'Content-Type, Authorization';
const PUBLIC_API_PATHS = new Set(['/api/breakdown', '/api/summary', '/api/timeseries', '/api/realtime']);

/**
 * The `src` the console prints in its install snippet.
 *
 * An instance preference rather than a deployment variable, because the answer
 * only exists after the deployment does: it depends on the hostname you ended
 * up on, the filename you chose for the tracker, and
 * whether you later put the dashboard behind Access on a hostname of its own. Empty — the normal case —
 * means the console works it out from its own origin.
 */
const SETTING_TRACKER_URL = 'tracker_url';

type AppEnv = { Bindings: Env; Variables: { user: UserRow } };
type AppContext = Context<AppEnv>;

const app = new Hono<AppEnv>();

function addCorsHeaders(response: Response, request: Request): Response {
  const headers = new Headers(response.headers);
  const origin = request.headers.get('Origin');

  headers.set('Access-Control-Allow-Origin', origin === CORS_ALLOW_ORIGIN ? origin : CORS_ALLOW_ORIGIN);
  headers.set('Access-Control-Allow-Methods', CORS_ALLOW_METHODS);
  headers.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS);
  headers.set('Access-Control-Max-Age', '86400');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/** Writing the filter cube can be turned off on very high-traffic instances. */
function cubeEnabled(env: Env): boolean {
  return (env.FILTERS ?? 'on').toLowerCase() !== 'off';
}

function iterationsFor(env: Env): number {
  const parsed = Number.parseInt(env.PBKDF2_ITERATIONS ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 15_000;
}

function isSecure(url: string): boolean {
  return new URL(url).protocol === 'https:';
}

function normalizeDomain(raw: string): string {
  return raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
}

async function setupComplete(env: Env): Promise<boolean> {
  return (await countUsers(env.DB)) > 0;
}

/**
 * Resolve the signed-in user, or null.
 *
 * The cookie signature is verified first, then the account is re-read from the
 * database. That second step is what makes a deleted account, a changed
 * password or a revoked role take effect on the very next request instead of
 * whenever the cookie happens to expire.
 */
async function loadUser(env: Env, cookie: string | undefined): Promise<UserRow | null> {
  const secret = await getSetting(env.DB, SETTING_SESSION_SECRET);
  if (!secret) return null;

  const claims = await readSession(secret, cookie);
  if (!claims) return null;

  const user = await getUserById(env.DB, claims.uid);
  if (!user || user.token_version !== claims.tv) return null;
  return user;
}

async function startSession(env: Env, user: UserRow): Promise<string> {
  let secret = await getSetting(env.DB, SETTING_SESSION_SECRET);
  if (!secret) {
    secret = randomHex(32);
    await setSetting(env.DB, SETTING_SESSION_SECRET, secret);
  }
  return issueSession(secret, { uid: user.id, tv: user.token_version });
}

function parseSiteIds(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((v) => Number(v)).filter((n) => Number.isInteger(n) && n > 0))];
}

/* ------------------------------------------------------- browser defences -- */

/**
 * The headers that go on every HTML surface this Worker serves.
 *
 * `frame-ancestors` is the load-bearing one. The console renders "Remove user"
 * and "Remove site" as ordinary buttons wired to authenticated DELETE calls, so
 * a page that could load the dashboard in a transparent frame could have an
 * owner destroy accounts while clicking on something else entirely.
 * X-Frame-Options repeats it for browsers old enough to predate the directive.
 *
 * `default-src 'self'` is affordable here only because it is already true:
 * typefaces, the country outlines and every API call come from this Worker, and
 * there is no third-party origin anywhere in the product. Enforcing that in the
 * browser turns a claim in the README into something a visitor can verify.
 *
 * `script-src` takes a per-request nonce rather than `'unsafe-inline'`, because
 * the console displays paths, referrers, UTM values and event names that anyone
 * on the internet can put into the database through the public ingest endpoint.
 * Every one of those is escaped where it is written into the page — this is a
 * second layer rather than the only one, which is exactly what it is for.
 *
 * Applied at each HTML response rather than by `app.use('*')` middleware, on
 * purpose. The tracker script and the ingest endpoint are fetched cross-origin
 * from other people's sites, where a content policy for this origin means
 * nothing and a stray header is only weight on the hottest path in the system.
 */
function securityHeaders(scriptSrc: string): Record<string, string> {
  return {
    'content-security-policy': [
      "default-src 'self'",
      `script-src ${scriptSrc}`,
      "style-src 'self' 'unsafe-inline'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; '),
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-store',
  };
}

/** Sign-in and setup run no script at all, so none needs to be allowed. */
const PAGE_HEADERS = securityHeaders("'none'");

app.use('*', async (c, next) => {
  const request = c.req.raw;

  if (request.method === 'OPTIONS') {
    const headers = new Headers();
    headers.set('Access-Control-Allow-Origin', CORS_ALLOW_ORIGIN);
    headers.set('Access-Control-Allow-Methods', CORS_ALLOW_METHODS);
    headers.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS);
    headers.set('Access-Control-Max-Age', '86400');
    c.res = new Response(null, { status: 204, headers });
    return;
  }

  await ensureSchema(c.env.DB);
  await next();

  const response = c.res;
  if (response) {
    c.res = addCorsHeaders(response, request);
  }
});

app.onError((err, c) => {
  console.error(JSON.stringify({ level: 'error', path: c.req.path, message: String(err) }));
  return c.json({ error: 'internal error' }, 500);
});

/* ---------------------------------------------------------------- ingest -- */

app.options('/api/event', () => corsPreflight());
app.post('/api/event', (c) => handleIngest(c.req.raw, c.env));

/* -------------------------------------------------------------- sessions -- */

app.use('/api/*', async (c, next) => {
  if (c.req.path === '/api/event' || c.req.path.startsWith('/api/fonts/')) return next();
  if (PUBLIC_API_PATHS.has(c.req.path)) return next();

  const user = await loadUser(c.env, getCookie(c, SESSION_COOKIE));
  if (!user) return c.json({ error: 'unauthorized' }, 401);

  c.set('user', user);
  return next();
});

app.get('/setup', async (c) => {
  if (await setupComplete(c.env)) return c.redirect('/login', 302);
  return c.html(setupPage(), 200, PAGE_HEADERS);
});

app.post('/setup', async (c) => {
  if (await setupComplete(c.env)) return c.redirect('/login', 302);

  const form = await c.req.parseBody();
  const email = normalizeEmail(String(form.email ?? ''));
  const password = String(form.password ?? '');
  const confirm = String(form.confirm ?? '');
  const domain = normalizeDomain(String(form.domain ?? ''));

  if (!isValidEmail(email)) return c.html(setupPage('Enter a valid email address.'), 400, PAGE_HEADERS);
  if (password.length < MIN_PASSWORD_LENGTH) {
    return c.html(
      setupPage(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`),
      400,
      PAGE_HEADERS,
    );
  }
  if (password !== confirm) return c.html(setupPage('Passwords do not match.'), 400, PAGE_HEADERS);
  if (!DOMAIN_PATTERN.test(domain)) {
    return c.html(setupPage('Enter a bare domain, for example example.com'), 400, PAGE_HEADERS);
  }

  const owner = await createFirstOwner(c.env.DB, email, password, iterationsFor(c.env));
  if (!owner) return c.redirect('/login', 302);

  await c.env.DB.prepare('INSERT OR IGNORE INTO sites (domain, created_at) VALUES (?, ?)')
    .bind(domain, Math.floor(Date.now() / 1000))
    .run();

  setCookie(c, SESSION_COOKIE, await startSession(c.env, owner), sessionCookieOptions(isSecure(c.req.url)));
  return c.redirect('/', 302);
});

app.get('/login', async (c) => {
  if (!(await setupComplete(c.env))) return c.redirect('/setup', 302);
  return c.html(loginPage(), 200, PAGE_HEADERS);
});

app.post('/login', async (c) => {
  if (!(await setupComplete(c.env))) return c.redirect('/setup', 302);

  const form = await c.req.parseBody();
  const email = normalizeEmail(String(form.email ?? ''));
  const password = String(form.password ?? '');

  const user = await getUserByEmail(c.env.DB, email);
  const ok = user !== null && (await verifyPassword(user, password, iterationsFor(c.env)));
  if (!user || !ok) {
    return c.html(loginPage('Incorrect email or password.'), 401, PAGE_HEADERS);
  }

  setCookie(c, SESSION_COOKIE, await startSession(c.env, user), sessionCookieOptions(isSecure(c.req.url)));
  return c.redirect('/', 302);
});

app.post('/logout', (c) => {
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
  return c.redirect('/login', 302);
});

/* ----------------------------------------------------------- own account -- */

app.get('/api/me', async (c) => {
  const user = c.get('user');
  return c.json({
    user: toPublicUser(user, await siteIdsFor(c.env.DB, user.id)),
    trackerUrl: (await getSetting(c.env.DB, SETTING_TRACKER_URL)) ?? '',
    version: VERSION,
    update: isOwner(user) ? await readUpdateStatus(c.env.DB) : null,
  });
});

app.post('/api/me/password', async (c) => {
  const user = c.get('user');
  const body = await c.req
    .json<{ current?: unknown; next?: unknown }>()
    .catch(() => ({}) as Record<string, unknown>);
  const current = String(body.current ?? '');
  const next = String(body.next ?? '');

  if (!(await verifyPassword(user, current, iterationsFor(c.env)))) {
    return c.json({ error: 'current password is incorrect' }, 400);
  }
  if (next.length < MIN_PASSWORD_LENGTH) {
    return c.json({ error: `password must be at least ${MIN_PASSWORD_LENGTH} characters` }, 400);
  }

  await setPassword(c.env.DB, user.id, next, iterationsFor(c.env));

  const updated = await getUserById(c.env.DB, user.id);
  if (updated) {
    setCookie(c, SESSION_COOKIE, await startSession(c.env, updated), sessionCookieOptions(isSecure(c.req.url)));
  }
  return c.json({ ok: true });
});

/* ----------------------------------------------------- instance settings -- */

export function normalizeTrackerUrl(raw: string): string | null {
  const value = raw.trim();
  if (!value) return '';

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (!url.pathname.endsWith('.js')) return null;
  return url.href;
}

app.put('/api/settings/tracker-url', async (c) => {
  if (!isOwner(c.get('user'))) return c.json({ error: 'owner access required' }, 403);

  const body = await c.req.json<{ url?: unknown }>().catch(() => ({}) as Record<string, unknown>);
  const trackerUrl = normalizeTrackerUrl(String(body.url ?? ''));
  if (trackerUrl === null) {
    return c.json({ error: 'enter a full URL ending in .js, or leave it empty' }, 400);
  }

  await setSetting(c.env.DB, SETTING_TRACKER_URL, trackerUrl);
  return c.json({ trackerUrl });
});

/* ----------------------------------------------------------------- sites -- */

app.get('/api/sites', async (c) => c.json({ sites: await accessibleSites(c.env.DB, c.get('user')) }));

app.post('/api/sites', async (c) => {
  if (!isOwner(c.get('user'))) return c.json({ error: 'owner access required' }, 403);

  const body = await c.req.json<{ domain?: unknown }>().catch(() => ({ domain: undefined }));
  const domain = normalizeDomain(String(body.domain ?? ''));
  if (!DOMAIN_PATTERN.test(domain)) return c.json({ error: 'invalid domain' }, 400);

  await c.env.DB.prepare('INSERT OR IGNORE INTO sites (domain, created_at) VALUES (?, ?)')
    .bind(domain, Math.floor(Date.now() / 1000))
    .run();
  return c.json({ sites: await accessibleSites(c.env.DB, c.get('user')) });
});

app.delete('/api/sites/:id', async (c) => {
  if (!isOwner(c.get('user'))) return c.json({ error: 'owner access required' }, 403);

  const id = Number.parseInt(c.req.param('id'), 10);
  if (!Number.isInteger(id)) return c.json({ error: 'invalid id' }, 400);

  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM site_access WHERE site_id = ?').bind(id),
    c.env.DB.prepare('DELETE FROM sites WHERE id = ?').bind(id),
  ]);
  return c.json({ sites: await accessibleSites(c.env.DB, c.get('user')) });
});

/* ----------------------------------------------------------------- users -- */

app.get('/api/users', async (c) => {
  if (!isOwner(c.get('user'))) return c.json({ error: 'owner access required' }, 403);
  return c.json({ users: await listUsers(c.env.DB) });
});

app.post('/api/users', async (c) => {
  if (!isOwner(c.get('user'))) return c.json({ error: 'owner access required' }, 403);

  const body = await c.req
    .json<{ email?: unknown; password?: unknown; role?: unknown; siteIds?: unknown }>()
    .catch(() => ({}) as Record<string, unknown>);

  const email = normalizeEmail(String(body.email ?? ''));
  const password = String(body.password ?? '');
  const role: Role = body.role === 'owner' ? 'owner' : 'viewer';

  if (!isValidEmail(email)) return c.json({ error: 'invalid email address' }, 400);
  if (password.length < MIN_PASSWORD_LENGTH) {
    return c.json({ error: `password must be at least ${MIN_PASSWORD_LENGTH} characters` }, 400);
  }

  const created = await createUser(
    c.env.DB,
    { email, password, role, siteIds: parseSiteIds(body.siteIds) },
    iterationsFor(c.env),
  );
  if (!created) return c.json({ error: 'that email address is already in use' }, 409);

  return c.json({ users: await listUsers(c.env.DB) });
});

app.patch('/api/users/:id', async (c) => {
  const actor = c.get('user');
  if (!isOwner(actor)) return c.json({ error: 'owner access required' }, 403);

  const id = Number.parseInt(c.req.param('id'), 10);
  const target = Number.isInteger(id) ? await getUserById(c.env.DB, id) : null;
  if (!target) return c.json({ error: 'no such user' }, 404);

  const body = await c.req
    .json<{ role?: unknown; siteIds?: unknown; password?: unknown }>()
    .catch(() => ({}) as Record<string, unknown>);

  if (body.role === 'owner' || body.role === 'viewer') {
    if (target.id === actor.id) return c.json({ error: 'you cannot change your own role' }, 400);
    if (target.role === 'owner' && body.role === 'viewer' && (await countOwners(c.env.DB)) === 1) {
      return c.json({ error: 'the last owner cannot be demoted' }, 400);
    }
    await setRole(c.env.DB, target.id, body.role);
  }

  if (body.siteIds !== undefined) {
    await setSiteAccess(c.env.DB, target.id, parseSiteIds(body.siteIds));
  }

  if (typeof body.password === 'string' && body.password !== '') {
    if (body.password.length < MIN_PASSWORD_LENGTH) {
      return c.json({ error: `password must be at least ${MIN_PASSWORD_LENGTH} characters` }, 400);
    }
    await setPassword(c.env.DB, target.id, body.password, iterationsFor(c.env));
  }

  return c.json({ users: await listUsers(c.env.DB) });
});

app.delete('/api/users/:id', async (c) => {
  const actor = c.get('user');
  if (!isOwner(actor)) return c.json({ error: 'owner access required' }, 403);

  const id = Number.parseInt(c.req.param('id'), 10);
  const target = Number.isInteger(id) ? await getUserById(c.env.DB, id) : null;
  if (!target) return c.json({ error: 'no such user' }, 404);

  if (target.id === actor.id) return c.json({ error: 'you cannot remove your own account' }, 400);
  if (target.role === 'owner' && (await countOwners(c.env.DB)) === 1) {
    return c.json({ error: 'the last owner cannot be removed' }, 400);
  }

  await deleteUser(c.env.DB, target.id);
  return c.json({ users: await listUsers(c.env.DB) });
});

/* ----------------------------------------------------------------- stats -- */

type SiteRow = Awaited<ReturnType<typeof accessibleSites>>[number];

async function resolveSite(c: AppContext): Promise<SiteRow | Response> {
  const user =
    c.get('user') ??
    ({
      id: 0,
      email: 'public@localhost',
      password_hash: '',
      password_salt: '',
      role: 'owner',
      token_version: 0,
      created_at: 0,
    } as UserRow);

  const sites = await accessibleSites(c.env.DB, user);
  if (sites.length === 0) return c.json({ error: 'no sites available' }, 404);

  const requested = Number.parseInt(c.req.query('site') ?? '', 10);
  if (!Number.isInteger(requested)) return sites[0]!;
  if (!(await canAccessSite(c.env.DB, user, requested))) {
    return c.json({ error: 'forbidden' }, 403);
  }

  const site = sites.find((s) => s.id === requested);
  return site ?? c.json({ error: 'no such site' }, 404);
}

/**
 * The dashboard's filter stack, plus the `event` a panel was opened on.
 *
 * The stack narrows pageviews; a custom event is a different row, so it cannot
 * ride along in `f` — the query layer would rightly drop a dimension it has no
 * column for. Naming it by hand is treated exactly like a click on it in the
 * Events panel: a filter on that event name, AND-ed with whatever else is set.
 * The dashboard names events this way precisely because the tracker keeps them
 * out of the pageview row's `f`.
 */
function resolveFilters(c: AppContext) {
  const filters = parseFilters(c.req.query('f'));
  const event = c.req.query('event');
  if (event) filters.push({ dim: 'event', value: event });
  return filters;
}

const NO_STORE = { 'cache-control': 'no-store' } as const;

function summarize(components: Components): Record<Metric, number> {
  return Object.fromEntries(METRICS.map((m) => [m, metricValue(m, components)])) as Record<
    Metric,
    number
  >;
}

app.get('/api/stats', async (c) => {
  const site = await resolveSite(c);
  if (site instanceof Response) return site;

  const now = new Date();
  const today = partsFor(now).day;
  const from = c.req.query('from') ?? dayOffset(now, -6);
  const to = c.req.query('to') ?? today;

  if (!isValidDay(from) || !isValidDay(to) || from > to) {
    return c.json({ error: 'invalid date range' }, 400);
  }

  await catchUpToday(c.env.DB, now);

  const stats = await getStats(c.env.DB, site.id, from, to, now);
  return c.json({ site, stats }, 200, NO_STORE);
});

app.get('/api/summary', async (c) => {
  const site = await resolveSite(c);
  if (site instanceof Response) return site;

  const now = new Date();
  const range = resolveRange(
    c.req.query('range'),
    c.req.query('from'),
    c.req.query('to'),
    now,
  );
  if (!range) return c.json({ error: 'invalid range' }, 400);

  const filters = parseFilters(c.req.query('f'));
  const compare = c.req.query('cmp') === '1';

  const started = Date.now();
  await catchUpToday(c.env.DB, now);
  const db = c.env.DB;

  const [series, previousSeries] = await Promise.all([
    loadSeries(db, site.id, range, range.from, range.to, filters, now),
    compare
      ? loadSeries(db, site.id, range, range.prevFrom, range.prevTo, filters, now)
      : Promise.resolve(null),
  ]);

  const totals = totalsFrom(series);
  const previousTotals = previousSeries ? totalsFrom(previousSeries) : null;

  const per = (buckets: typeof series | null): Record<Metric, number[]> | null =>
    buckets &&
    (Object.fromEntries(
      METRICS.map((m) => [m, buckets.map((b) => metricValue(m, b))]),
    ) as Record<Metric, number[]>);

  return c.json(
    {
      site,
      range,
      filters,
      totals: summarize(totals),
      previous: previousTotals ? summarize(previousTotals) : null,
      series: {
        labels: series.map((b) => b.label),
        cur: per(series),
        prev: previousSeries ? per(previousSeries.slice(0, series.length)) : null,
      },
      visitsBasis: filters.some((f) => f.dim === 'path') ? 'entrances' : 'exact',
      meta: { ms: Date.now() - started, colo: (c.req.raw.cf?.colo as string | undefined) ?? '' },
    },
    200,
    NO_STORE,
  );
});

app.get('/api/timeseries', async (c) => {
  const site = await resolveSite(c);
  if (site instanceof Response) return site;

  const now = new Date();
  const range = resolveRange(c.req.query('range'), c.req.query('from'), c.req.query('to'), now);
  if (!range) return c.json({ error: 'invalid range' }, 400);

  const requested = c.req.query('metric') ?? 'visitors';
  if (!(METRICS as readonly string[]).includes(requested)) {
    return c.json({ error: 'unknown metric' }, 400);
  }
  const metric = requested as Metric;
  // Carries `event` too, so a series can be drawn for one game rather than the
  // whole site. The metric goes with it: an event has firings to count and no
  // visitors, so the series counts its views whatever metric was asked for.
  const filters = resolveFilters(c);
  const compare = c.req.query('cmp') === '1';

  await catchUpToday(c.env.DB, now);

  // An event fires; it has no visits of its own to count, so a series for one
  // counts its firings whatever metric was asked for — the rule the Events
  // panel counts by. Everything else is answered exactly as before.
  const seriesMetric: Metric = filters.some((f) => f.dim === 'event') ? 'views' : metric;

  const series = await loadSeries(
    c.env.DB,
    site.id,
    range,
    range.from,
    range.to,
    filters,
    now,
    seriesMetric,
  );
  const previous = compare
    ? await loadSeries(
        c.env.DB,
        site.id,
        range,
        range.prevFrom,
        range.prevTo,
        filters,
        now,
        seriesMetric,
      )
    : [];

  return c.json(
    {
      granularity: range.granularity,
      points: series.map((bucket, i) => ({
        label: bucket.label,
        cur: metricValue(seriesMetric, bucket),
        prev: previous[i] ? metricValue(seriesMetric, previous[i]!) : null,
      })),
    },
    200,
    NO_STORE,
  );
});

app.get('/api/breakdown', async (c) => {
  const site = await resolveSite(c);
  if (site instanceof Response) return site;

  const now = new Date();
  const range = resolveRange(c.req.query('range'), c.req.query('from'), c.req.query('to'), now);
  if (!range) return c.json({ error: 'invalid range' }, 400);

  const dims = (c.req.query('dim') ?? 'path').split(',').map((d) => d.trim()).filter(isBreakdownDim);
  if (dims.length === 0) return c.json({ error: 'unknown dimension' }, 400);

  const parsed = Number.parseInt(c.req.query('limit') ?? '', 10);
  const limit = Number.isInteger(parsed) ? Math.min(Math.max(parsed, 1), 50) : 10;
  const filters = parseFilters(c.req.query('f'));

  await catchUpToday(c.env.DB, now);

  const breakdowns = await loadBreakdowns(c.env.DB, site.id, range, filters, dims, limit, now);

  return c.json(
    { breakdowns, rows: dims.length === 1 ? breakdowns[dims[0]!] : undefined },
    200,
    NO_STORE,
  );
});

app.get('/api/realtime', async (c) => {
  const site = await resolveSite(c);
  if (site instanceof Response) return site;
  return c.json(await loadRealtime(c.env.DB, site.id, new Date()), 200, NO_STORE);
});

app.get('/api/world.json', (c) =>
  c.json(WORLD_GEOMETRY, 200, { 'cache-control': 'public, max-age=31536000, immutable' }),
);

app.get('/api/fonts/:file', (c) => {
  const file = c.req.param('file');
  if (!Object.hasOwn(FONT_FILES, file)) return c.notFound();
  const encoded = FONT_FILES[file]!;

  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

  return c.body(bytes, 200, {
    'content-type': 'font/woff2',
    'cache-control': 'public, max-age=31536000, immutable',
  });
});

/* ------------------------------------------------------------- dashboard -- */

const dashboardTemplateWithFonts = dashboardTemplate.replace('/*fonts*/', FONT_FACE_CSS);

app.get('/', async (c) => {
  if (!(await setupComplete(c.env))) return c.redirect('/setup', 302);
  const user = await loadUser(c.env, getCookie(c, SESSION_COOKIE));
  if (!user) return c.redirect('/login', 302);

  const nonce = randomHex(16);
  return c.html(
    dashboardTemplateWithFonts.replace('{{nonce}}', nonce),
    200,
    securityHeaders(`'nonce-${nonce}'`),
  );
});

app.get('/gamecheck', (c) => c.html(gamecheckPage, 200));

app.get('/health', (c) => c.json({ ok: true }));

app.get('/robots.txt', (c) => c.text('User-agent: *\nDisallow: /\n'));

const faviconResponse = (c: AppContext) =>
  c.body(FAVICON_SVG, 200, {
    'content-type': 'image/svg+xml',
    'cache-control': 'public, max-age=86400',
  });

app.get('/favicon.svg', faviconResponse);
app.get('/favicon.ico', faviconResponse);

app.get('/:file{[A-Za-z0-9._-]+\\.js}', (c) => {
  if (RESERVED_PATHS.has(c.req.param('file'))) return c.notFound();
  return trackerResponse();
});

app.options('/:name{[A-Za-z0-9._-]+}', (c) => {
  if (RESERVED_PATHS.has(c.req.param('name'))) return c.notFound();
  return corsPreflight();
});

app.post('/:name{[A-Za-z0-9._-]+}', (c) => {
  if (RESERVED_PATHS.has(c.req.param('name'))) return c.notFound();
  return handleIngest(c.req.raw, c.env);
});

export default {
  fetch: app.fetch,

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const run = async (): Promise<void> => {
      await ensureSchema(env.DB);
      const now = new Date(controller.scheduledTime);
      const retention = Number.parseInt(env.HOURLY_RETENTION_DAYS ?? '', 10);

      const daily = controller.cron.startsWith('20 0 ');

      try {
        if (daily) {
          await dailyJob(env.DB, now, Number.isFinite(retention) ? retention : 7, cubeEnabled(env));
        } else {
          await hourlyJob(env.DB, now);
        }
      } catch (error) {
        console.error(JSON.stringify({ level: 'error', job: controller.cron, message: String(error) }));
        throw error;
      }

      if (daily) {
        try {
          await checkForUpdate(env);
        } catch (error) {
          console.error(JSON.stringify({ level: 'warn', job: 'update-check', message: String(error) }));
        }
      }
    };

    ctx.waitUntil(run());
  },
} satisfies ExportedHandler<Env>;
