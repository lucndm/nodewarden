// Runs the production SQL on an in-memory SQLite database so tests exercise
// the real schema statements instead of a hand-written subset.
//
// The shim answers the D1 surface the storage and backup code uses:
// prepare/bind/run/all/first plus batch. `batch` runs its statements in
// order, which is enough for the shadow-table swap the backup restore does.
//
// The shim also keeps D1's limit on bound parameters. SQLite itself takes far
// more than a hundred, so a statement that D1 would refuse passes here
// unnoticed unless the limit is part of the shim.
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';

const isQuery = (sql: string) => /^\s*(select|with|pragma)/i.test(sql);

// D1 refuses a statement with more bound parameters than this.
export const D1_MAX_SQL_VARIABLES = 100;

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
          if (values.length > D1_MAX_SQL_VARIABLES) {
            throw new Error(`too many SQL variables: ${values.length} (D1 allows ${D1_MAX_SQL_VARIABLES})`);
          }
          if (isQuery(sql)) {
            return { success: true, meta: { changes: 0 }, results: sqlite.prepare(sql).all(...values) };
          }
          const result = sqlite.prepare(sql).run(...values);
          return { success: true, meta: { changes: Number(result.changes) }, results: [] };
        },
        async all() {
          if (values.length > D1_MAX_SQL_VARIABLES) {
            throw new Error(`too many SQL variables: ${values.length} (D1 allows ${D1_MAX_SQL_VARIABLES})`);
          }
          return { success: true, meta: { changes: 0 }, results: sqlite.prepare(sql).all(...values) };
        },
        async first() {
          if (values.length > D1_MAX_SQL_VARIABLES) {
            throw new Error(`too many SQL variables: ${values.length} (D1 allows ${D1_MAX_SQL_VARIABLES})`);
          }
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
