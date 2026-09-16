import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OpaqueToken } from '../src/crypto/opaque-token.js';
import { ActionTokenStore } from '../src/store/action-token-store.js';
import { EventStore } from '../src/store/event-store.js';
import { SessionStore } from '../src/store/session-store.js';
import { UserStore } from '../src/store/user-store.js';
import { testDb } from './helpers.js';

test('UserStore normalises email, paginates and tracks login failures with lockout', () => {
  const db = testDb();
  const users = new UserStore(db);
  const u = users.create({ email: '  Ali@Example.COM ', name: 'Ali', passwordHash: 'h' }, 1000);
  assert.equal(u.email, 'ali@example.com');
  assert.equal(users.byEmail('ALI@example.com')?.id, u.id);
  assert.throws(() => users.create({ email: 'ali@example.com', passwordHash: 'h' }), /UNIQUE/);

  const u2 = users.create({ email: 'b@example.com', passwordHash: 'h' }, 2000);
  const u3 = users.create({ email: 'c@example.com', passwordHash: 'h' }, 3000);
  assert.deepEqual(users.list({ limit: 2 }).map((r) => r.id), [u3.id, u2.id]);
  assert.deepEqual(users.list({ limit: 2, before: { createdAt: u2.created_at, id: u2.id } }).map((r) => r.id), [u.id]);
  assert.deepEqual(users.counts(), { total: 3, active: 3, disabled: 0 });

  let r = users.recordLoginFailure(u.id, { maxFailures: 2, lockoutMs: 60_000, now: 5000 });
  assert.deepEqual({ ...r }, { failed_logins: 1, locked_until: null });
  r = users.recordLoginFailure(u.id, { maxFailures: 2, lockoutMs: 60_000, now: 5000 });
  assert.deepEqual({ ...r }, { failed_logins: 2, locked_until: 65_000 });
  users.recordLoginSuccess(u.id, 6000);
  assert.equal(users.byId(u.id)?.failed_logins, 0);
  assert.equal(users.byId(u.id)?.locked_until, null);

  users.markVerified(u.id, 7000);
  users.markVerified(u.id, 8000);
  assert.equal(users.byId(u.id)?.email_verified_at, 7000, 'first verification wins');
  users.setStatus(u.id, 'disabled', 9000);
  assert.equal(users.counts().disabled, 1);
  users.setPassword(u.id, 'h2', 9500);
  assert.equal(users.byId(u.id)?.password_changed_at, 9500);
  assert.equal(users.remove(u.id), true);
  assert.equal(users.remove(u.id), false);
});

test('SessionStore rotates tokens, detects previous-token replay and revokes', () => {
  const db = testDb();
  const users = new UserStore(db);
  const sessions = new SessionStore(db);
  const u = users.create({ email: 'a@b.co', passwordHash: 'h' });
  const { session, refreshToken } = sessions.create({ userId: u.id, ttlMs: 1000, ip: '1.2.3.4', userAgent: 'ua' }, 0);
  assert.equal(session.expires_at, 1000);
  assert.equal(sessions.findByToken(refreshToken)?.current, true);
  assert.equal(sessions.findByToken('nope'), undefined);

  const next = sessions.rotate(session.id, { now: 10 });
  assert.notEqual(next, refreshToken);
  assert.equal(sessions.findByToken(next)?.current, true);
  assert.equal(sessions.findByToken(refreshToken)?.current, false, 'old token still resolves for reuse detection');
  assert.equal(sessions.byId(session.id)?.previous_token_hash, OpaqueToken.hash(refreshToken));

  const third = sessions.rotate(session.id, { now: 20 });
  assert.equal(sessions.findByToken(refreshToken), undefined, 'only one generation back is kept');
  assert.equal(sessions.findByToken(third)?.current, true);

  assert.equal(sessions.activeForUser(u.id, 500).length, 1);
  assert.equal(sessions.activeForUser(u.id, 1001).length, 0, 'expired excluded');
  assert.equal(sessions.revoke(session.id, 30), true);
  assert.equal(sessions.revoke(session.id, 30), false);
  assert.throws(() => sessions.rotate(session.id), /revoked/);

  sessions.create({ userId: u.id, ttlMs: 1000 }, 0);
  sessions.create({ userId: u.id, ttlMs: 1000 }, 0);
  assert.equal(sessions.revokeAllForUser(u.id, 40), 2);
  assert.equal(sessions.countActive(50), 0);
  assert.equal(sessions.purge(0, 35), 1, 'revoked before 35');
  assert.equal(sessions.purge(2000, 0), 2, 'expired');
  assert.equal(users.remove(u.id), true);
});

test('ActionTokenStore issues single-use tokens and invalidates earlier ones', () => {
  const db = testDb();
  const users = new UserStore(db);
  const tokens = new ActionTokenStore(db);
  const u = users.create({ email: 'a@b.co', passwordHash: 'h' });
  const t1 = tokens.issue({ userId: u.id, purpose: 'verify_email', ttlMs: 1000 }, 0);
  const t2 = tokens.issue({ userId: u.id, purpose: 'verify_email', ttlMs: 1000 }, 10);
  assert.equal(tokens.consume(t1, 'verify_email', 20), undefined, 'superseded token is dead');
  assert.equal(tokens.consume(t2, 'reset_password', 20), undefined, 'purpose must match');
  assert.equal(tokens.consume(t2, 'verify_email', 20)?.user_id, u.id);
  assert.equal(tokens.consume(t2, 'verify_email', 21), undefined, 'single use');
  const t3 = tokens.issue({ userId: u.id, purpose: 'reset_password', ttlMs: 100 }, 0);
  assert.equal(tokens.consume(t3, 'reset_password', 100), undefined, 'expired at boundary');
  assert.equal(tokens.consume('garbage', 'reset_password', 0), undefined);
  assert.equal(tokens.issuedSince(u.id, 'verify_email', 5), 1);
  assert.equal(tokens.issuedSince(u.id, 'verify_email', 0), 1, 'strictly after');
  assert.equal(tokens.purge(200, 200), 3);
});

test('EventStore records and pages events', () => {
  const db = testDb();
  const events = new EventStore(db);
  for (let i = 0; i < 5; i++) events.record({ userId: 'u', type: `t${i}`, meta: { i } }, i);
  events.record({ type: 'anon' }, 9);
  const page = events.forUser('u', { limit: 2 });
  assert.deepEqual(page.map((e) => e.type), ['t4', 't3']);
  assert.deepEqual(JSON.parse(page[0].meta ?? ''), { i: 4 });
  assert.deepEqual(events.forUser('u', { limit: 10, beforeId: page[1].id }).map((e) => e.type), ['t2', 't1', 't0']);
  assert.equal(events.purge(3), 3);
});

test('ActionTokenStore.peek reads without consuming', () => {
  const db = testDb();
  const users = new UserStore(db);
  const tokens = new ActionTokenStore(db);
  const u = users.create({ email: 'a@b.co', passwordHash: 'h' });
  const t = tokens.issue({ userId: u.id, purpose: 'reset_password', ttlMs: 1000 }, 0);
  assert.equal(tokens.peek(t, 'reset_password', 10)?.user_id, u.id);
  assert.equal(tokens.peek(t, 'reset_password', 10)?.user_id, u.id, 'still there');
  assert.equal(tokens.peek(t, 'verify_email', 10), undefined);
  assert.equal(tokens.peek(t, 'reset_password', 1000), undefined, 'expired');
  assert.ok(tokens.consume(t, 'reset_password', 10));
  assert.equal(tokens.peek(t, 'reset_password', 10), undefined, 'consumed');
});
