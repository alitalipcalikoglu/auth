import assert from 'node:assert/strict';
import { readFileSync, statSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { KeyGenerator } from '../scripts/keygen.js';
import { JwtSigner } from '../src/crypto/jwt.js';

const dir = mkdtempSync(join(tmpdir(), 'auth-keygen-'));
after(() => rmSync(dir, { recursive: true, force: true }));

test('KeyGenerator writes a usable ES256 pair with private mode 0600 and refuses to overwrite', async () => {
  const out = new KeyGenerator(join(dir, 'jwt')).run();
  assert.equal(statSync(out.privatePath).mode & 0o777, 0o600);
  const signer = new JwtSigner({ privateKeyPem: readFileSync(out.privatePath, 'utf8'), previousPublicKeyPem: readFileSync(out.publicPath, 'utf8'), issuer: 'https://i', audience: 'a', ttlSec: 60 });
  await signer.init();
  assert.equal(signer.jwks().keys.length, 2);
  assert.equal(signer.jwks().keys[0].kid, signer.jwks().keys[1].kid, 'public file matches private key');
  assert.throws(() => new KeyGenerator(join(dir, 'jwt')).run(), /refusing to overwrite/);
});
