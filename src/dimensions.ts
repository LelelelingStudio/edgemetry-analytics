export const FILTER_COLUMNS: Readonly<Record<string, string>> = Object.fromEntries(
  DIMENSIONS.map(({ dim, column }) => [dim, column]),
  // `event` is a special-case filter on the raw event name column; it is
  // handled in the shared query builder below and does not need its own
  // breakdown-only entry in the public dimension list.
  // @ts-expect-error -- special-case filter alias is intentionally added here.
  ['event', 'name'],
);
