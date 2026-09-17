import assert from 'node:assert/strict';
import { test } from 'node:test';
import { JwtError, JwtSigner } from '../src/crypto/jwt.js';
import { OpaqueToken } from '../src/crypto/opaque-token.js';
import { PasswordHasher } from '../src/crypto/password.js';
import { testKeyPair, testSigner } from './helpers.js';

test('PasswordHasher hashes with a random salt and verifies in constant time', async () => {
  const h = new PasswordHasher({ logN: 14 });
  const a = await h.hash('correct horse battery staple');
  const b = await h.hash('correct horse battery staple');
  assert.notEqual(a, b, 'salts differ');
  assert.match(a, /^scrypt\$14\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  assert.equal(await h.verify('correct horse battery staple', a), true);
  assert.equal(await h.verify('Correct horse battery staple', a), false);
  assert.equal(await h.verify('x', 'garbage'), false);
  assert.equal(await h.verify('x', 'scrypt$14$8$1$short$short'), false);
  assert.equal(await h.verify('ﬁsh', await h.hash('fish')), true, 'NFKC normalisation');
});

test('PasswordHasher.needsRehash flags weaker parameters', async () => {
  const weak = await new PasswordHasher({ logN: 14 }).hash('pw');
  assert.equal(new PasswordHasher({ logN: 14 }).needsRehash(weak), false);
  assert.equal(new PasswordHasher({ logN: 15 }).needsRehash(weak), true);
  assert.equal(new PasswordHasher({ logN: 14 }).needsRehash('garbage'), true);
  assert.throws(() => new PasswordHasher({ logN: 8 }), RangeError);
});

test('PasswordHasher.dummyHash: same cost parameters as a real hash at that logN, no real password behind it', async () => {
  const dummy14 = PasswordHasher.dummyHash(14);
  const dummy15 = PasswordHasher.dummyHash(15);
  assert.match(dummy14, /^scrypt\$14\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  assert.match(dummy15, /^scrypt\$15\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  const parsed14 = PasswordHasher.parse(dummy14);
  const parsed15 = PasswordHasher.parse(dummy15);
  assert.deepEqual([parsed14?.logN, parsed15?.logN], [14, 15], 'cost parameter follows the requested logN, not a fixed value');
  // A hasher configured at logN 15 must burn as much CPU verifying against the dummy as against a
  // real logN-15 hash: same cost parameters, so the scrypt work factor (N = 2^logN) matches.
  const h15 = new PasswordHasher({ logN: 15 });
  assert.equal(await h15.verify('anything', dummy15), false, 'dummy hash never verifies as a match');
  assert.equal(new PasswordHasher({ logN: 15 }).needsRehash(dummy14), true, 'a logN-14 dummy is recognised as weaker cost than 15');
  assert.equal(new PasswordHasher({ logN: 15 }).needsRehash(dummy15), false, 'a logN-15 dummy matches the current cost exactly');
});

test('OpaqueToken generates 256-bit url-safe secrets with stable hashes', () => {
  const { token, hash } = OpaqueToken.generate();
  assert.equal(OpaqueToken.looksValid(token), true);
  assert.equal(hash, OpaqueToken.hash(token));
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.notEqual(OpaqueToken.generate().token, token);
  assert.equal(OpaqueToken.looksValid('short'), false);
  assert.equal(OpaqueToken.looksValid(`${token}!`), false);
  assert.equal(OpaqueToken.looksValid(42), false);
});

test('JwtSigner signs ES256 tokens with kid and verifies issuer, audience, expiry', async () => {
  const { signer } = await testSigner({ ttlSec: 60 });
  const now = Date.now();
  const { token, expiresAt, jti } = await signer.sign({ sub: 'u1', sid: 's1', email: 'a@b.co', email_verified: true }, now);
  assert.equal(expiresAt, Math.floor(now / 1000) * 1000 + 60_000);
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
  assert.equal(header.alg, 'ES256');
  assert.equal(header.kid, signer.kid);

  const claims = await signer.verify(token);
  assert.equal(claims.sub, 'u1');
  assert.equal(claims.sid, 's1');
  assert.equal(claims.email_verified, true);
  assert.equal(claims.jti, jti);
  assert.equal(claims.iss, 'https://auth.test.local');

  const jwks = signer.jwks();
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].kid, signer.kid);
  assert.equal(jwks.keys[0].alg, 'ES256');
  assert.equal('d' in jwks.keys[0], false, 'private component never published');

  const expired = await signer.sign({ sub: 'u1', sid: 's1', email: 'a@b.co', email_verified: false }, now - 120_000);
  await assert.rejects(signer.verify(expired.token), (e) => e instanceof JwtError && e.code === 'EXPIRED');
  await assert.rejects(signer.verify(`${token}x`), (e) => e instanceof JwtError && e.code === 'INVALID');

  const other = await testSigner();
  const foreign = await other.signer.sign({ sub: 'u1', sid: 's1', email: 'a@b.co', email_verified: false });
  await assert.rejects(signer.verify(foreign.token), (e) => e instanceof JwtError && e.code === 'UNKNOWN_KEY');

  const wrongAud = new JwtSigner({ privateKeyPem: other.pair.privatePem, issuer: 'https://auth.test.local', audience: 'someone-else', ttlSec: 60 });
  await wrongAud.init();
  const audToken = await wrongAud.sign({ sub: 'u1', sid: 's1', email: 'a@b.co', email_verified: false });
  const verifier = new JwtSigner({ privateKeyPem: other.pair.privatePem, issuer: 'https://auth.test.local', audience: 'test-app', ttlSec: 60 });
  await verifier.init();
  await assert.rejects(verifier.verify(audToken.token), (e) => e instanceof JwtError && e.code === 'INVALID');
});

test('JwtSigner accepts tokens from the previous key during rotation', async () => {
  const old = await testSigner();
  const token = await old.signer.sign({ sub: 'u1', sid: 's1', email: 'a@b.co', email_verified: false });
  const rotated = new JwtSigner({ privateKeyPem: testKeyPair().privatePem, previousPublicKeyPem: old.pair.publicPem, issuer: 'https://auth.test.local', audience: 'test-app', ttlSec: 60 });
  await rotated.init();
  assert.equal(rotated.jwks().keys.length, 2);
  assert.equal((await rotated.verify(token.token)).sub, 'u1');
  const fresh = await rotated.sign({ sub: 'u2', sid: 's2', email: 'b@b.co', email_verified: false });
  assert.equal((await rotated.verify(fresh.token)).sub, 'u2');
  assert.notEqual(JSON.parse(Buffer.from(fresh.token.split('.')[0], 'base64url').toString()).kid, old.signer.kid);
});
