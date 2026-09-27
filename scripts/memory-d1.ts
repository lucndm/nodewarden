// In-memory D1 stand-in shared by handler tests. Supports the SQL subset
// the flows under test execute (see sso-mobile-flow.test.ts for background).

type Row = Record<string, unknown>;

function topLevelSplit(input: string, separator: RegExp): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (const char of input) {
    if (char === '(') depth++;
    if (char === ')') depth--;
    if (depth === 0 && separator.test(char)) {
      parts.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  parts.push(current);
  return parts.map((part) => part.trim()).filter(Boolean);
}

export const PRIMARY_KEY_BUILDERS: Record<string, (row: Row) => string> = {
  users: (row) => String(row.id),
  ciphers: (row) => String(row.id),
  user_revisions: (row) => String(row.user_id),
  devices: (row) => `${row.user_id}|${row.device_identifier}`,
  sso_authorization_codes: (row) => String(row.code_hash),
  refresh_tokens: (row) => String(row.token),
  audit_logs: (row) => String(row.id),
  config: (row) => String(row.key),
  email_breach_cache: (row) => String(row.email_norm),
  login_attempts_ip: (row) => String(row.ip),
};

class MemoryStatement {
  private values: unknown[] = [];

  constructor(
    private readonly db: MemoryD1,
    private readonly sql: string
  ) {}

  bind(...values: unknown[]): this {
    this.values = values;
    return this;
  }

  async first<T = Row>(): Promise<T | null> {
    const { results } = this.select();
    return (results[0] as T) ?? null;
  }

  async all<T = Row>(): Promise<{ results: T[]; success: true }> {
    return { results: this.select().results as T[], success: true };
  }

  async run(): Promise<{ success: true; meta: { changes: number } }> {
    const sql = this.sql.replace(/\s+/g, ' ').trim();
    if (/^create /i.test(sql)) return { success: true, meta: { changes: 0 } };
    if (/^insert /i.test(sql)) return this.insert();
    if (/^update /i.test(sql)) return this.update();
    if (/^delete /i.test(sql)) return this.deleteRows();
    throw new Error(`MemoryD1: unsupported statement: ${this.sql}`);
  }

  /** Evaluates WHERE equality/comparison conditions against in-memory rows. */
  private matches(rows: Row[], whereClause: string | undefined, bindStart: number): Row[] {
    if (!whereClause) return rows;
    const conditions = whereClause.split(/\s+AND\s+/i).map((condition) => condition.trim());
    return rows.filter((row) => {
      // Placeholder binds are positional per row: every row evaluates the same
      // conditions against the same bound values, starting at bindStart.
      let bindIndex = bindStart;
      for (const condition of conditions) {
        const isNull = condition.match(/^(\w+)\s+IS\s+NULL$/i);
        if (isNull) {
          if (row[isNull[1]] != null) return false;
          continue;
        }
        const comparison = condition.match(/^(\w+)\s*(=|<>|<=|>=|<|>)\s*\?$/i);
        if (!comparison) throw new Error(`MemoryD1: unsupported condition: ${condition}`);
        const [, column, operator] = comparison;
        const expected = this.values[bindIndex++];
        const actual = row[column];
        switch (operator) {
          case '=':
            if (actual !== expected) return false;
            break;
          case '<>':
            if (actual === expected) return false;
            break;
          case '<':
            if (!(Number(actual) < Number(expected))) return false;
            break;
          case '<=':
            if (!(Number(actual) <= Number(expected))) return false;
            break;
          case '>':
            if (!(Number(actual) > Number(expected))) return false;
            break;
          case '>=':
            if (!(Number(actual) >= Number(expected))) return false;
            break;
        }
      }
      return true;
    });
  }

  private select(): { results: Row[] } {
    const countMatch = this.sql.match(/select\s+count\(\*\)\s+as\s+(\w+)\s+from\s+(\w+)/i);
    if (countMatch) {
      const filtered = this.matches(this.db.rows(countMatch[2]), undefined, 0);
      return { results: [{ [countMatch[1]]: filtered.length }] };
    }

    const match = this.sql.match(
      /^select\s+(.+?)\s+from\s+(\w+)(?:\s+where\s+(.+?))?(?:\s+order\s+by\s+.+?)?(?:\s+limit\s+\d+)?\s*$/i
    );
    if (!match) throw new Error(`MemoryD1: unsupported SELECT: ${this.sql}`);

    const wherePlaceholders = (match[3]?.match(/\?/g) ?? []).length;
    const rows = this.matches(this.db.rows(match[2]), match[3], 0);
    const columns = match[1].trim() === '*' ? null : topLevelSplit(match[1], /,/);
    const results = rows.map((row) => {
      if (!columns) return { ...row };
      const projected: Row = {};
      for (const column of columns) {
        projected[column] = row[column];
      }
      return projected;
    });
    return { results };
  }

  private insert(): { success: true; meta: { changes: number } } {
    const match = this.sql.match(
      /^insert\s+(or\s+ignore\s+)?into\s+(\w+)\s*\(([^)]+)\)\s*values\s*\((.+?)\)(\s*on\s+conflict.+)?$/i
    );
    if (!match) throw new Error(`MemoryD1: unsupported INSERT: ${this.sql}`);

    const [, orIgnore, table, columnList, valuesClause, conflictClause] = match;
    const columns = topLevelSplit(columnList, /,/);
    const valueTokens = topLevelSplit(valuesClause.replace(/^\(/, '').replace(/\)$/, ''), /,/);
    if (columns.length !== valueTokens.length) {
      throw new Error(`MemoryD1: column/value mismatch: ${this.sql}`);
    }

    let bindIndex = 0;
    const row: Row = {};
    columns.forEach((column, index) => {
      const token = valueTokens[index];
      if (/^\?+$/.test(token)) {
        row[column] = this.values[bindIndex++];
      } else if (/^null$/i.test(token)) {
        row[column] = null;
      } else if (/^\d+$/.test(token)) {
        row[column] = Number(token);
      } else {
        throw new Error(`MemoryD1: unsupported VALUES token '${token}' in: ${this.sql}`);
      }
    });

    const store = this.db.table(table);
    const pk = PRIMARY_KEY_BUILDERS[table]?.(row);
    const existing = pk ? store.get(pk) : undefined;

    if (existing && orIgnore) return { success: true, meta: { changes: 0 } };

    if (existing && conflictClause) {
      const clause = conflictClause.replace(/\s+/g, ' ').trim();
      if (table === 'devices' && clause.includes('ON CONFLICT(user_id, device_identifier)')) {
        // Mirrors the CASE/COALESCE upsert semantics in storage-device-repo.ts:
        // non-empty existing session stamp and push uuid win; COALESCE keeps the
        // stored key material when the new value is NULL.
        const firstNonEmpty = (value: unknown, fallback: unknown) =>
          value == null || value === '' ? fallback : value;
        store.set(pk!, {
          ...existing,
          name: row.name,
          type: row.type,
          session_stamp: firstNonEmpty(existing.session_stamp, row.session_stamp),
          encrypted_user_key: row.encrypted_user_key ?? existing.encrypted_user_key,
          encrypted_public_key: row.encrypted_public_key ?? existing.encrypted_public_key,
          encrypted_private_key: row.encrypted_private_key ?? existing.encrypted_private_key,
          push_uuid: firstNonEmpty(existing.push_uuid, row.push_uuid),
          last_seen_at: row.last_seen_at,
          updated_at: row.updated_at,
        });
        return { success: true, meta: { changes: 1 } };
      }
      if (table === 'users' || table === 'refresh_tokens') {
        // DO UPDATE SET lists every column except created_at.
        store.set(pk!, { ...row, created_at: existing.created_at });
        return { success: true, meta: { changes: 1 } };
      }
      // config-style full replacement.
      store.set(pk!, row);
      return { success: true, meta: { changes: 1 } };
    }

    if (!pk) throw new Error(`MemoryD1: no primary key rule for table '${table}'`);
    store.set(pk, row);
    return { success: true, meta: { changes: 1 } };
  }

  private update(): { success: true; meta: { changes: number } } {
    const match = this.sql.match(/^update\s+(\w+)\s+set\s+(.+?)\s+where\s+(.+?)\s*$/i);
    if (!match) throw new Error(`MemoryD1: unsupported UPDATE: ${this.sql}`);

    const [, table, assignmentsClause, whereClause] = match;
    // Placeholders bind left to right: SET assignments first, WHERE values last.
    const whereBindStart = this.values.length - (whereClause.match(/\?/g) ?? []).length;
    const rows = this.matches(this.db.rows(table), whereClause, whereBindStart);

    let bindIndex = 0;
    for (const row of rows) {
      for (const assignment of topLevelSplit(assignmentsClause, /,/)) {
        const literal = assignment.match(/^(\w+)\s*=\s*\?$/i);
        if (literal) {
          row[literal[1]] = this.values[bindIndex++];
          continue;
        }
        const increment = assignment.match(/^(\w+)\s*=\s*\w+\s*\+\s*(\?|\d+)$/i);
        if (increment) {
          const delta = increment[2] === '?' ? Number(this.values[bindIndex++]) : Number(increment[2]);
          row[increment[1]] = Number(row[increment[1]]) + delta;
          continue;
        }
        throw new Error(`MemoryD1: unsupported assignment: ${assignment}`);
      }
    }
    return { success: true, meta: { changes: rows.length } };
  }

  private deleteRows(): { success: true; meta: { changes: number } } {
    const match = this.sql.match(/^delete\s+from\s+(\w+)(?:\s+where\s+(.+?))?\s*$/i);
    if (!match) throw new Error(`MemoryD1: unsupported DELETE: ${this.sql}`);

    const store = this.db.table(match[1]);
    const rows = this.matches(this.db.rows(match[1]), match[2], 0);
    for (const row of rows) {
      const pk = PRIMARY_KEY_BUILDERS[match[1]]?.(row);
      if (pk) store.delete(pk);
    }
    return { success: true, meta: { changes: rows.length } };
  }
}

export class MemoryD1 {
  private tables = new Map<string, Map<string, Row>>();

  table(name: string): Map<string, Row> {
    let table = this.tables.get(name);
    if (!table) {
      table = new Map();
      this.tables.set(name, table);
    }
    return table;
  }

  rows(name: string): Row[] {
    return [...this.table(name).values()];
  }

  prepare(sql: string): {
    bind: (...values: unknown[]) => MemoryStatement;
    first: <T = Row>() => Promise<T | null>;
    all: <T = Row>() => Promise<{ results: T[]; success: true }>;
    run: () => Promise<{ success: true; meta: { changes: number } }>;
  } {
    const statement = new MemoryStatement(this, sql);
    return {
      bind: (...values: unknown[]) => statement.bind(...values),
      first: <T>() => statement.first<T>(),
      all: <T>() => statement.all<T>(),
      run: () => statement.run(),
    };
  }
}
