import { createHash, randomBytes } from 'node:crypto';

/**
 * High-entropy bearer secrets (refresh, verify, reset). Only the SHA-256 hash is stored;
 * the plaintext is shown to the caller once.
 */
export class OpaqueToken {
  static BYTES = 32;

  /** @returns {{ token: string, hash: string }} */
  static generate() {
    const token = randomBytes(OpaqueToken.BYTES).toString('base64url');
    return { token, hash: OpaqueToken.hash(token) };
  }

  /**
   * @param {string} token
   * @returns {string} hex SHA-256
   */
  static hash(token) {
    return createHash('sha256').update(token).digest('hex');
  }

  /**
   * Shape check before hitting the database.
   * @param {unknown} token
   */
  static looksValid(token) {
    return typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token);
  }
}
