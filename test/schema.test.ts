import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

import { ensureSchema } from '../src/db';

describe('schema initialization', () => {
  it('does not share an in-flight initialization between concurrent requests', async () => {
    let batches = 0;
    const db = new Proxy(env.DB, {
      get(target, property, receiver) {
        if (property === 'batch') {
          return (statements: D1PreparedStatement[]) => {
            batches += 1;
            return target.batch(statements);
          };
        }
        return Reflect.get(target, property, receiver);
      },
    });

    await Promise.all([ensureSchema(db), ensureSchema(db)]);

    expect(batches).toBe(2);
  });
});
