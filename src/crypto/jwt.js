import { createPublicKey, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { calculateJwkThumbprint, importJWK, importPKCS8, jwtVerify, SignJWT } from 'jose';

/** @typedef {import('./../types.js').AccessClaims} AccessClaims */

export class JwtError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = 'JwtError';
    this.code = code;
  }
}

/**
 * ES256 access tokens. Signs with the current private key, verifies against the current
 * public key and an optional previous one so rotation does not invalidate live tokens.
 * Call {@link init} before use.
 */
export class JwtSigner {
  static ALG = 'ES256';

  /**
   * @param {object} opts
   * @param {string} opts.privateKeyPem          PKCS#8 PEM.
   * @param {string|null} [opts.previousPublicKeyPem]  SPKI PEM.
   * @param {string} opts.issuer
   * @param {string} opts.audience
   * @param {number} opts.ttlSec
   */
  constructor({ privateKeyPem, previousPublicKeyPem = null, issuer, audience, ttlSec }) {
    this.privateKeyPem = privateKeyPem;
    this.previousPublicKeyPem = previousPublicKeyPem;
    this.issuer = issuer;
    this.audience = audience;
    this.ttlSec = ttlSec;
    /** @type {import('jose').CryptoKey|null} */
    this.privateKey = null;
    /** @type {{ kid: string, key: import('jose').CryptoKey, jwk: import('jose').JWK }[]} */
    this.publicKeys = [];
  }

  /**
   * Convenience for the composition root.
   * @param {{ privateKeyPath: string, previousPublicKeyPath: string|null, issuer: string, audience: string, ttlSec: number }} o
   */
  static fromFiles(o) {
    return new JwtSigner({
      privateKeyPem: readFileSync(o.privateKeyPath, 'utf8'),
      previousPublicKeyPem: o.previousPublicKeyPath ? readFileSync(o.previousPublicKeyPath, 'utf8') : null,
      issuer: o.issuer,
      audience: o.audience,
      ttlSec: o.ttlSec,
    });
  }

  /** Import keys and compute key ids (RFC 7638 thumbprints). */
  async init() {
    this.privateKey = await importPKCS8(this.privateKeyPem, JwtSigner.ALG);
    this.publicKeys = [await JwtSigner.#publicEntry(this.privateKeyPem)];
    if (this.previousPublicKeyPem) this.publicKeys.push(await JwtSigner.#publicEntry(this.previousPublicKeyPem));
    return this;
  }

  /**
   * Public JWK (x, y only) plus verification key and RFC 7638 thumbprint for a PEM key.
   * @param {string} pem Private PKCS#8 or public SPKI.
   */
  static async #publicEntry(pem) {
    const exported = createPublicKey(pem).export({ format: 'jwk' });
    if (exported.kty !== 'EC' || exported.crv !== 'P-256') throw new Error('JWT key must be an EC P-256 key');
    /** @type {import('jose').JWK} */
    const jwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y };
    const kid = await calculateJwkThumbprint(jwk);
    const key = /** @type {import('jose').CryptoKey} */ (await importJWK({ ...jwk, alg: JwtSigner.ALG }, JwtSigner.ALG));
    return { kid, key, jwk: { ...jwk, kid, alg: JwtSigner.ALG, use: 'sig' } };
  }

  get kid() {
    return this.publicKeys[0].kid;
  }

  /**
   * @param {AccessClaims} claims
   * @param {number} [now] Epoch ms.
   * @returns {Promise<{ token: string, expiresAt: number, jti: string }>}
   */
  async sign(claims, now = Date.now()) {
    if (!this.privateKey) throw new Error('JwtSigner.init() not called');
    const iat = Math.floor(now / 1000);
    const exp = iat + this.ttlSec;
    const jti = randomUUID();
    const token = await new SignJWT({ sid: claims.sid, email: claims.email, email_verified: claims.email_verified })
      .setProtectedHeader({ alg: JwtSigner.ALG, kid: this.kid, typ: 'JWT' })
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setSubject(claims.sub)
      .setJti(jti)
      .setIssuedAt(iat)
      .setExpirationTime(exp)
      .sign(this.privateKey);
    return { token, expiresAt: exp * 1000, jti };
  }

  /**
   * Verify signature, algorithm, issuer, audience and expiry.
   * @param {string} token
   * @returns {Promise<AccessClaims & { jti: string, exp: number, iat: number, iss: string, aud: string }>}
   */
  async verify(token) {
    try {
      const { payload } = await jwtVerify(token, (header) => {
        const entry = this.publicKeys.find((k) => k.kid === header.kid);
        if (!entry) throw new JwtError('UNKNOWN_KEY', 'token signed with an unknown key');
        return entry.key;
      }, { algorithms: [JwtSigner.ALG], issuer: this.issuer, audience: this.audience });
      return /** @type {any} */ (payload);
    } catch (err) {
      if (err instanceof JwtError) throw err;
      const code = /** @type {{ code?: string }} */ (err).code === 'ERR_JWT_EXPIRED' ? 'EXPIRED' : 'INVALID';
      throw new JwtError(code, code === 'EXPIRED' ? 'token expired' : 'token invalid');
    }
  }

  /** JWKS document for `/.well-known/jwks.json`. */
  jwks() {
    return { keys: this.publicKeys.map((k) => k.jwk) };
  }
}
