/**
 * The database instance: the one file in db/ that you write.
 *
 * The CLI creates this file only when it does not exist yet and never
 * overwrites it, not even with --force, so your code here survives
 * re-generation. Everything else in db/ is generated.
 *
 * This OP keeps its data in Cloudflare D1 (the DB binding in wrangler.jsonc).
 * The tables of schema.sql are applied as migrations/0001_init.sql with
 * wrangler d1 migrations, and scripts/lib/seed.ts registers the clients and
 * the test user with registerClient() / registerUser().
 */
import type { Context } from 'hono';
import type { SqlDatabase, SqlStatement } from './database.js';

export function createDatabase(c: Context): SqlDatabase {
  const d1 = c.env.DB as D1Database;
  return {
    async all<Row>(statement: SqlStatement): Promise<Row[]> {
      const result = await d1.prepare(statement.sql).bind(...statement.params).all<Row>();
      return result.results;
    },
    async run(statement: SqlStatement) {
      const result = await d1.prepare(statement.sql).bind(...statement.params).run();
      return { changes: result.meta.changes };
    },
  };
}
