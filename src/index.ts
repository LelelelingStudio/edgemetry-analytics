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
