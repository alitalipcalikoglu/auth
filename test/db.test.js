import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Database } from '../src/db.js';

test('Database applies migrations once and enforces foreign keys', () => {
  const db = new Database(':memory:');
  const tables = /** @type {{ name: string }[]} */ (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all()).map((r) => r.name);
  assert.deepEqual(tables, ['action_tokens', 'events', 'schema_migrations', 'sessions', 'users']);
  assert.equal(/** @type {{ user_version: number }} */ (db.prepare('PRAGMA user_version').get()).user_version, Database.MIGRATIONS.length);
  assert.throws(() => db.prepare("INSERT INTO sessions (id,user_id,token_hash,created_at,last_used_at,expires_at) VALUES ('s','missing','h',0,0,0)").run(), /FOREIGN KEY/);
  db.ping();
  db.close();
});

test('Database.transaction commits on success and rolls back on throw', () => {
  const db = new Database(':memory:');
  const insert = db.prepare("INSERT INTO events (type, at) VALUES (?, 0)");
  db.transaction(() => { insert.run('a'); insert.run('b'); });
  assert.throws(() => db.transaction(() => { insert.run('c'); throw new Error('boom'); }), /boom/);
  assert.equal(/** @type {{ n: number }} */ (db.prepare('SELECT COUNT(*) n FROM events').get()).n, 2);
});
