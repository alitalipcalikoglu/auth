import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AuditEvents } from '../src/domain/audit-events.js';
import { AuditClient } from '../src/net/audit-client.js';
import { Database } from '../src/db.js';
import { EventStore } from '../src/store/event-store.js';

const silent = { warn() {}, error() {} };

test('AuditClient: buffers, batches with idempotent ids, retries, drops rejected batches, no-op when off', async () => {
  /** @type {{ body: any, auth: string|undefined }[]} */ const calls = [];
  let fail = 2;
  const c = new AuditClient({ target: { url: 'http://audit.test/', apiKey: 'a'.repeat(40) }, batchSize: 2, logger: silent, sleep: async () => {}, fetch: /** @type {typeof fetch} */ (async (_url, init) => {
    calls.push({ body: JSON.parse(String(init?.body)), auth: /** @type {any} */ (init?.headers).authorization });
    return new Response(fail-- > 0 ? 'down' : '{}', { status: fail >= 0 ? 503 : 200 });
  }) });
  c.record({ action: 'x.one' }); c.record({ action: 'x.two' }); c.record({ action: 'x.three' });
  await c.flush();
  assert.deepEqual([calls.length, calls[0].auth, calls[0].body.events.length, c.stats.sent, c.buffer.length], [4, `Bearer ${'a'.repeat(40)}`, 2, 3, 0]);
  assert.equal(calls[0].body.events[0].id, calls[2].body.events[0].id, 'retries resend the same ids');
  const dead = new AuditClient({ target: { url: 'http://audit.test', apiKey: 'a'.repeat(40) }, logger: silent, sleep: async () => {}, fetch: async () => { throw new Error('ECONNREFUSED'); } });
  dead.record({ action: 'x.kept' });
  await dead.flush();
  assert.deepEqual([dead.stats.failed, dead.buffer.length], [1, 1]);
  assert.equal(new AuditClient({ target: null }).record({ action: 'x' }), false);
});

test('security events are forwarded as auth.* audit events with outcome, actor and target', () => {
  const db = new Database(':memory:');
  const events = new EventStore(db);
  const audit = new AuditClient({ target: { url: 'http://audit.test', apiKey: 'a'.repeat(40) }, logger: silent });
  events.onRecord = (e, at) => { audit.record(AuditEvents.fromSecurityEvent(e, at)); };
  const at = Date.parse('2026-09-17T10:00:00Z');
  events.record({ userId: 'u1', type: 'login.failed', ip: '203.0.113.9', meta: { reason: 'bad_password', failures: 2 } }, at);
  events.record({ type: 'login.failed', ip: '203.0.113.9', meta: { reason: 'unknown_email' } }, at);
  events.record({ userId: 'u1', type: 'login.succeeded', ip: '203.0.113.9', meta: { sessionId: 's1' } }, at);
  const [a, b, c] = audit.buffer;
  assert.deepEqual([a.action, a.outcome, a.actor, a.target, a.ip, a.meta, a.at], ['auth.login.failed', 'failure', { type: 'user', id: 'u1' }, { type: 'user', id: 'u1' }, '203.0.113.9', { reason: 'bad_password', failures: 2 }, '2026-09-17T10:00:00.000Z']);
  assert.deepEqual([b.actor, b.target, b.outcome], [undefined, undefined, 'failure']);
  assert.deepEqual([c.action, c.outcome], ['auth.login.succeeded', 'success']);
  assert.equal(events.forUser('u1', { limit: 10 }).length, 2, 'local log still written');
});
