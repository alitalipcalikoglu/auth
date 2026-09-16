/** @typedef {import('./types.js').ApiKey} ApiKey */

export class ConfigError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

/** Validated service configuration. Build with {@link Config.fromEnv}. */
export class Config {
  static MIN_SECRET_LENGTH = 32;

  /** @param {import('./types.js').ConfigValues} v */
  constructor(v) {
    this.port = v.port;
    this.host = v.host;
    this.logLevel = v.logLevel;
    this.trustProxy = v.trustProxy;
    this.tls = v.tls;
    this.bodyLimit = v.bodyLimit;
    this.dbPath = v.dbPath;
    this.apiKeys = v.apiKeys;
    this.rateLimitMax = v.rateLimitMax;
    this.jwtPrivateKeyPath = v.jwtPrivateKeyPath;
    this.jwtPreviousPublicKeyPath = v.jwtPreviousPublicKeyPath;
    this.jwtIssuer = v.jwtIssuer;
    this.jwtAudience = v.jwtAudience;
    this.accessTokenTtlSec = v.accessTokenTtlSec;
    this.refreshTokenTtlDays = v.refreshTokenTtlDays;
    this.verifyTokenTtlMin = v.verifyTokenTtlMin;
    this.resetTokenTtlMin = v.resetTokenTtlMin;
    this.passwordMinLength = v.passwordMinLength;
    this.scryptLogN = v.scryptLogN;
    this.loginMaxFailures = v.loginMaxFailures;
    this.loginLockoutMin = v.loginLockoutMin;
    this.loginRequiresVerifiedEmail = v.loginRequiresVerifiedEmail;
    this.resendCooldownSec = v.resendCooldownSec;
    this.notifyUrl = v.notifyUrl;
    this.notifyApiKey = v.notifyApiKey;
    this.notifyTimeoutMs = v.notifyTimeoutMs;
    this.appName = v.appName;
    this.emailLocale = v.emailLocale;
    this.verifyUrlTemplate = v.verifyUrlTemplate;
    this.resetUrlTemplate = v.resetUrlTemplate;
    this.eventRetentionDays = v.eventRetentionDays;
    Object.freeze(this);
  }

  /**
   * @param {NodeJS.ProcessEnv} [env]
   * @returns {Config}
   */
  static fromEnv(env = process.env) {
    const r = new EnvReader(env);

    const certPath = r.optional('TLS_CERT_PATH');
    const keyPath = r.optional('TLS_KEY_PATH');
    if (Boolean(certPath) !== Boolean(keyPath)) throw new ConfigError('TLS_CERT_PATH and TLS_KEY_PATH must be set together');

    const jwtIssuer = r.required('JWT_ISSUER');
    if (!/^https?:\/\/[^\s]+$/.test(jwtIssuer)) throw new ConfigError('JWT_ISSUER must be an absolute http(s) URL');

    const notifyUrl = r.required('NOTIFY_URL').replace(/\/+$/, '');
    if (!/^https?:\/\/[^\s]+$/.test(notifyUrl)) throw new ConfigError('NOTIFY_URL must be an absolute http(s) URL');
    const notifyApiKey = r.required('NOTIFY_API_KEY');
    if (notifyApiKey.length < Config.MIN_SECRET_LENGTH) throw new ConfigError(`NOTIFY_API_KEY must be at least ${Config.MIN_SECRET_LENGTH} characters`);

    const emailLocale = r.optional('EMAIL_LOCALE') || 'tr';
    if (emailLocale !== 'tr' && emailLocale !== 'en') throw new ConfigError('EMAIL_LOCALE must be tr or en');

    return new Config({
      port: r.integer('PORT', 3002, { min: 1, max: 65535 }),
      host: r.optional('HOST') || '0.0.0.0',
      logLevel: r.optional('LOG_LEVEL') || 'info',
      trustProxy: r.boolean('TRUST_PROXY', false),
      tls: certPath ? { certPath, keyPath } : null,
      bodyLimit: r.integer('BODY_LIMIT', 16_384, { min: 1_024 }),
      dbPath: r.optional('DB_PATH') || './data/auth.db',
      apiKeys: Config.#parseApiKeys(r.required('AUTH_API_KEYS')),
      rateLimitMax: r.integer('RATE_LIMIT_MAX', 600, { min: 1 }),
      jwtPrivateKeyPath: r.required('JWT_PRIVATE_KEY_PATH'),
      jwtPreviousPublicKeyPath: r.optional('JWT_PREVIOUS_PUBLIC_KEY_PATH') || null,
      jwtIssuer,
      jwtAudience: r.required('JWT_AUDIENCE'),
      accessTokenTtlSec: r.integer('ACCESS_TOKEN_TTL_SEC', 900, { min: 60, max: 86_400 }),
      refreshTokenTtlDays: r.integer('REFRESH_TOKEN_TTL_DAYS', 30, { min: 1, max: 365 }),
      verifyTokenTtlMin: r.integer('VERIFY_TOKEN_TTL_MIN', 1_440, { min: 5 }),
      resetTokenTtlMin: r.integer('RESET_TOKEN_TTL_MIN', 60, { min: 5, max: 1_440 }),
      passwordMinLength: r.integer('PASSWORD_MIN_LENGTH', 10, { min: 8, max: 128 }),
      scryptLogN: r.integer('SCRYPT_LOG_N', 15, { min: 14, max: 20 }),
      loginMaxFailures: r.integer('LOGIN_MAX_FAILURES', 10, { min: 3, max: 100 }),
      loginLockoutMin: r.integer('LOGIN_LOCKOUT_MIN', 15, { min: 1 }),
      loginRequiresVerifiedEmail: r.boolean('LOGIN_REQUIRES_VERIFIED_EMAIL', false),
      resendCooldownSec: r.integer('RESEND_COOLDOWN_SEC', 60, { min: 0, max: 3_600 }),
      notifyUrl,
      notifyApiKey,
      notifyTimeoutMs: r.integer('NOTIFY_TIMEOUT_MS', 5_000, { min: 500, max: 60_000 }),
      appName: r.required('APP_NAME'),
      emailLocale,
      verifyUrlTemplate: Config.#urlTemplate(r.required('VERIFY_URL_TEMPLATE'), 'VERIFY_URL_TEMPLATE'),
      resetUrlTemplate: Config.#urlTemplate(r.required('RESET_URL_TEMPLATE'), 'RESET_URL_TEMPLATE'),
      eventRetentionDays: r.integer('EVENT_RETENTION_DAYS', 90, { min: 1 }),
    });
  }

  /**
   * @param {string} value
   * @param {string} name
   */
  static #urlTemplate(value, name) {
    if (!/^https:\/\/[^\s]+$/.test(value)) throw new ConfigError(`${name} must be an absolute https URL`);
    if (!value.includes('{token}')) throw new ConfigError(`${name} must contain {token}`);
    return value;
  }

  /**
   * Parse `id:secret,id2:secret2`.
   * @param {string} raw
   * @returns {ApiKey[]}
   */
  static #parseApiKeys(raw) {
    const keys = raw.split(',').map((s) => s.trim()).filter(Boolean).map((entry) => {
      const idx = entry.indexOf(':');
      if (idx <= 0) throw new ConfigError(`AUTH_API_KEYS entry "${entry.slice(0, 8)}…" must be id:secret`);
      const id = entry.slice(0, idx);
      const secret = entry.slice(idx + 1);
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new ConfigError(`AUTH_API_KEYS id "${id}" must match [A-Za-z0-9_-]{1,64}`);
      if (secret.length < Config.MIN_SECRET_LENGTH) {
        throw new ConfigError(`AUTH_API_KEYS secret for "${id}" must be at least ${Config.MIN_SECRET_LENGTH} characters`);
      }
      return { id, secret };
    });
    if (keys.length === 0) throw new ConfigError('AUTH_API_KEYS must contain at least one key');
    if (new Set(keys.map((k) => k.id)).size !== keys.length) throw new ConfigError('AUTH_API_KEYS ids must be unique');
    return keys;
  }
}

/** Typed accessors over a raw environment map. */
class EnvReader {
  /** @param {NodeJS.ProcessEnv} env */
  constructor(env) {
    this.env = env;
  }

  /** @param {string} name */
  optional(name) {
    return this.env[name]?.trim() ?? '';
  }

  /** @param {string} name */
  required(name) {
    const v = this.optional(name);
    if (v === '') throw new ConfigError(`${name} is required`);
    return v;
  }

  /**
   * @param {string} name
   * @param {number} fallback
   * @param {{ min?: number, max?: number }} [range]
   */
  integer(name, fallback, range = {}) {
    const raw = this.optional(name);
    if (raw === '') return fallback;
    if (!/^-?\d+$/.test(raw)) throw new ConfigError(`${name} must be an integer, got "${raw}"`);
    const n = Number(raw);
    if (range.min !== undefined && n < range.min) throw new ConfigError(`${name} must be >= ${range.min}`);
    if (range.max !== undefined && n > range.max) throw new ConfigError(`${name} must be <= ${range.max}`);
    return n;
  }

  /**
   * @param {string} name
   * @param {boolean} fallback
   */
  boolean(name, fallback) {
    const raw = this.optional(name);
    if (raw === '') return fallback;
    if (raw === 'true' || raw === '1') return true;
    if (raw === 'false' || raw === '0') return false;
    throw new ConfigError(`${name} must be true or false, got "${raw}"`);
  }
}
