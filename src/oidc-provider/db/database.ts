/**
 * The database contract of the generated OP (--db).
 *
 * db/stores.ts and db/clients.ts run every query through these two methods,
 * and db/instance.ts creates the object that implements them for your
 * database. Any driver or ORM can implement them, because every one of them
 * can run raw SQL.
 *
 * - Values are bound with ? placeholders, in order. An adapter for a driver
 *   that numbers its placeholders (PostgreSQL: $1, $2, ...) rewrites each ?
 *   into the next number; the generated SQL never has a ? inside a literal.
 * - Bound values are only strings, numbers and null: times are epoch seconds
 *   and objects are JSON text. Booleans are never bound. The statements write
 *   them as the literals TRUE / FALSE, because not every PostgreSQL driver
 *   accepts a bound number for a BOOLEAN column.
 * - Rows come back the way the driver returns them. stores.ts reads a BIGINT
 *   that pg returns as a string, and a BOOLEAN that SQLite returns as 1 / 0.
 * - There is no transaction API. Each store operation runs its statements one
 *   at a time, and the database applies a statement's condition and its
 *   change together.
 */
export type SqlValue = string | number | null;

export interface SqlStatement {
  sql: string;
  params: SqlValue[];
}

export interface SqlDatabase {
  /** Run a statement that returns rows (SELECT, DELETE ... RETURNING). */
  all<Row>(statement: SqlStatement): Promise<Row[]>;
  /** Run a statement that returns no rows (INSERT, UPDATE, DELETE) and report how many rows it changed. */
  run(statement: SqlStatement): Promise<{ changes: number }>;
}
