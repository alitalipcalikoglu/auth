import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

/**
 * Generates the ES256 (EC P-256) signing key pair used for access tokens.
 *   npm run keygen [-- keys/jwt]
 * Writes `<base>-private.pem` (PKCS#8, mode 0600) and `<base>-public.pem` (SPKI).
 * Refuses to overwrite existing files: rotate by generating under a new name and pointing
 * JWT_PREVIOUS_PUBLIC_KEY_PATH at the old public key.
 */
export class KeyGenerator {
  /** @param {string} base Path prefix without extension. */
  constructor(base) {
    this.privatePath = `${base}-private.pem`;
    this.publicPath = `${base}-public.pem`;
  }

  run() {
    for (const p of [this.privatePath, this.publicPath]) {
      if (existsSync(p)) throw new Error(`${p} already exists, refusing to overwrite`);
    }
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    mkdirSync(dirname(this.privatePath), { recursive: true });
    writeFileSync(this.privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    writeFileSync(this.publicPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
    return { privatePath: this.privatePath, publicPath: this.publicPath };
  }
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const out = new KeyGenerator(process.argv[2] ?? 'keys/jwt').run();
  console.log(`private key: ${out.privatePath}\npublic key:  ${out.publicPath}`);
}
