import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = /** @type {(password: string, salt: Buffer, keylen: number, options: import('node:crypto').ScryptOptions) => Promise<Buffer>} */ (promisify(scrypt));

/**
 * scrypt password hashing. Stored format: `scrypt$<logN>$<r>$<p>$<salt>$<hash>` (base64url),
 * so cost parameters can be raised later and old hashes detected with {@link needsRehash}.
 */
export class PasswordHasher {
  static SALT_BYTES = 32;
  static KEY_BYTES = 32;
  static R = 8;
  static P = 1;

  /** @param {{ logN?: number }} [opts] */
  constructor({ logN = 15 } = {}) {
    if (logN < 14 || logN > 20) throw new RangeError('scrypt logN must be between 14 and 20');
    this.logN = logN;
  }

  /**
   * @param {string} password
   * @returns {Promise<string>}
   */
  async hash(password) {
    const salt = randomBytes(PasswordHasher.SALT_BYTES);
    const key = await this.#derive(password, salt, this.logN, PasswordHasher.R, PasswordHasher.P);
    return ['scrypt', this.logN, PasswordHasher.R, PasswordHasher.P, salt.toString('base64url'), key.toString('base64url')].join('$');
  }

  /**
   * Constant-time verification against a stored hash. Malformed hashes verify as false.
   * @param {string} password
   * @param {string} stored
   * @returns {Promise<boolean>}
   */
  async verify(password, stored) {
    const parsed = PasswordHasher.parse(stored);
    if (!parsed) return false;
    const key = await this.#derive(password, parsed.salt, parsed.logN, parsed.r, parsed.p);
    return key.length === parsed.hash.length && timingSafeEqual(key, parsed.hash);
  }

  /**
   * True when a stored hash uses weaker parameters than the current configuration.
   * @param {string} stored
   */
  needsRehash(stored) {
    const parsed = PasswordHasher.parse(stored);
    return !parsed || parsed.logN < this.logN || parsed.r !== PasswordHasher.R || parsed.p !== PasswordHasher.P;
  }

  /**
   * @param {string} stored
   * @returns {{ logN: number, r: number, p: number, salt: Buffer, hash: Buffer }|null}
   */
  static parse(stored) {
    const parts = stored.split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return null;
    const [logN, r, p] = parts.slice(1, 4).map(Number);
    if (![logN, r, p].every(Number.isInteger) || logN < 10 || logN > 24) return null;
    const salt = Buffer.from(parts[4], 'base64url');
    const hash = Buffer.from(parts[5], 'base64url');
    if (salt.length < 16 || hash.length < 16) return null;
    return { logN, r, p, salt, hash };
  }

  /**
   * @param {string} password
   * @param {Buffer} salt
   * @param {number} logN
   * @param {number} r
   * @param {number} p
   * @returns {Promise<Buffer>}
   */
  #derive(password, salt, logN, r, p) {
    const N = 2 ** logN;
    return scryptAsync(password.normalize('NFKC'), salt, PasswordHasher.KEY_BYTES, { N, r, p, maxmem: 128 * N * r * 2 });
  }
}
