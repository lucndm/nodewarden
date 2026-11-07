// Runs the production SQL on an in-memory SQLite database so tests exercise
// the real schema statements instead of a hand-written subset.
//
// The shim answers the D1 surface the storage and backup code uses:
// prepare/bind/run/all/first plus batch. `batch` runs its statements in
// order, which is enough for the shadow-table swap the backup restore does.
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';

const isQuery = (sql: string) => /^\s*(select|with|pragma)/i.test(sql);

export function sqliteD1(sqlite: DatabaseSync): D1Database {
  const db = {
    prepare(sql: string) {
      let values: SQLInputValue[] = [];
      const statement = {
        bind(...bound: SQLInputValue[]) {
          values = bound;
          return statement;
        },
        async run() {
          if (isQuery(sql)) {
            return { success: true, meta: { changes: 0 }, results: sqlite.prepare(sql).all(...values) };
          }
          const result = sqlite.prepare(sql).run(...values);
          return { success: true, meta: { changes: Number(result.changes) }, results: [] };
        },
        async all() {
          return { success: true, meta: { changes: 0 }, results: sqlite.prepare(sql).all(...values) };
        },
        async first() {
          return sqlite.prepare(sql).get(...values) ?? null;
        },
      };
      return statement;
    },
    async batch(statements: D1PreparedStatement[]) {
      const results = [];
      for (const statement of statements) {
        results.push(await statement.run());
      }
      return results;
    },
  };
  // The D1 binding type is much wider than the subset used here.
  return db as unknown as D1Database;
}
