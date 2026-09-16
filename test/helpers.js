import { generateKeyPairSync } from 'node:crypto';
import { Config } from '../src/config.js';
import { JwtSigner } from '../src/crypto/jwt.js';
import { Database } from '../src/db.js';

export const API_KEY = 'k'.repeat(40);
export const OTHER_KEY = 'o'.repeat(40);

/** Fresh ES256 key pair as PEM strings. */
export function testKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    privatePem: /** @type {string} */ (privateKey.export({ type: 'pkcs8', format: 'pem' })),
    publicPem: /** @type {string} */ (publicKey.export({ type: 'spki', format: 'pem' })),
  };
}

/** Full valid environment; tests override single values. */
export function fullEnv() {
  return {
    AUTH_API_KEYS: `test:${API_KEY},other:${OTHER_KEY}`,
    JWT_PRIVATE_KEY_PATH: '/keys/jwt-private.pem',
    JWT_ISSUER: 'https://auth.test.local',
    JWT_AUDIENCE: 'test-app',
    NOTIFY_URL: 'http://127.0.0.1:1/',
    NOTIFY_API_KEY: 'n'.repeat(40),
    APP_NAME: 'Shop',
    VERIFY_URL_TEMPLATE: 'https://shop.test.local/verify?token={token}',
    RESET_URL_TEMPLATE: 'https://shop.test.local/reset?token={token}',
    DB_PATH: ':memory:',
    SCRYPT_LOG_N: '14',
    LOG_LEVEL: 'silent',
  };
}

/** @param {Record<string, string>} [overrides] */
export function testConfig(overrides = {}) {
  return Config.fromEnv({ ...fullEnv(), ...overrides });
}

/**
 * Initialised signer with an in-memory key pair.
 * @param {{ previousPublicPem?: string|null, ttlSec?: number }} [opts]
 */
export async function testSigner({ previousPublicPem = null, ttlSec = 900 } = {}) {
  const pair = testKeyPair();
  const signer = new JwtSigner({ privateKeyPem: pair.privatePem, previousPublicKeyPem: previousPublicPem, issuer: 'https://auth.test.local', audience: 'test-app', ttlSec });
  await signer.init();
  return { signer, pair };
}

export function testDb() {
  return new Database(':memory:');
}

/** Silent pino-compatible logger. */
export const silentLog = /** @type {any} */ (new Proxy({}, {
  get: (_t, prop) => (prop === 'child' ? () => silentLog : () => {}),
}));
