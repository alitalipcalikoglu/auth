import { Config } from './config.js';
import { AuditClient } from './net/audit-client.js';
import { AuditEvents } from './domain/audit-events.js';
import { JwtSigner } from './crypto/jwt.js';
import { PasswordHasher } from './crypto/password.js';
import { Database } from './db.js';
import { AuthService } from './domain/auth-service.js';
import { NotifyMailer } from './domain/mailer.js';
import { PasswordPolicy } from './domain/password-policy.js';
import { AuthApi } from './http/auth-api.js';
import { Maintenance } from './maintenance.js';
import { ActionTokenStore } from './store/action-token-store.js';
import { EventStore } from './store/event-store.js';
import { SessionStore } from './store/session-store.js';
import { UserStore } from './store/user-store.js';

/**
 * Composition root: wires configuration, storage, crypto, domain, HTTP and maintenance,
 * and owns the process lifecycle.
 */
export class Application {
  /** @param {Config} config */
  constructor(config) {
    this.config = config;
    this.audit = new AuditClient({ target: config.audit });
    this.db = new Database(config.dbPath);
    this.users = new UserStore(this.db);
    this.sessions = new SessionStore(this.db);
    this.tokens = new ActionTokenStore(this.db);
    this.events = new EventStore(this.db);
    this.events.onRecord = (e, at) => { this.audit.record(AuditEvents.fromSecurityEvent(e, at)); };
    this.jwt = JwtSigner.fromFiles({
      privateKeyPath: config.jwtPrivateKeyPath,
      previousPublicKeyPath: config.jwtPreviousPublicKeyPath,
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      ttlSec: config.accessTokenTtlSec,
    });
    this.mailer = new NotifyMailer({ baseUrl: config.notifyUrl, apiKey: config.notifyApiKey, appName: config.appName, locale: config.emailLocale, timeoutMs: config.notifyTimeoutMs });
    /** @type {import('fastify').FastifyInstance|null} */
    this.app = null;
    /** @type {Maintenance|null} */
    this.maintenance = null;
    this.shuttingDown = false;
  }

  /** Build from `process.env`; exits with a readable message on bad configuration. */
  static fromEnv() {
    try {
      return new Application(Config.fromEnv());
    } catch (err) {
      if (err instanceof Error && err.name === 'ConfigError') {
        console.error(`configuration error: ${err.message}`);
        process.exit(1);
      }
      throw err;
    }
  }

  async start() {
    const { config } = this;
    await this.jwt.init();
    const service = new AuthService({
      db: this.db, users: this.users, sessions: this.sessions, tokens: this.tokens, events: this.events,
      hasher: new PasswordHasher({ logN: config.scryptLogN }),
      policy: new PasswordPolicy({ minLength: config.passwordMinLength }),
      jwt: this.jwt, mailer: this.mailer, log: /** @type {any} */ (console),
      options: {
        refreshTtlMs: config.refreshTokenTtlDays * 86_400_000,
        verifyTtlMs: config.verifyTokenTtlMin * 60_000,
        resetTtlMs: config.resetTokenTtlMin * 60_000,
        loginMaxFailures: config.loginMaxFailures,
        lockoutMs: config.loginLockoutMin * 60_000,
        loginRequiresVerifiedEmail: config.loginRequiresVerifiedEmail,
        resendCooldownMs: config.resendCooldownSec * 1000,
        verifyUrlTemplate: config.verifyUrlTemplate,
        resetUrlTemplate: config.resetUrlTemplate,
      },
    });
    const api = new AuthApi({ config, audit: this.audit, service, jwt: this.jwt, db: this.db, mailer: this.mailer, users: this.users, sessions: this.sessions, events: this.events });
    const app = await api.build();
    this.app = app;
    service.log = app.log.child({ component: 'auth' });
    this.maintenance = new Maintenance({ sessions: this.sessions, tokens: this.tokens, events: this.events, log: app.log.child({ component: 'maintenance' }), options: { eventRetentionDays: config.eventRetentionDays } });
    this.#installSignalHandlers(app.log);
    this.audit.logger = app.log;
    this.audit.start();
    await app.listen({ port: config.port, host: config.host });
    app.log.info({ tls: config.tls !== null, kid: this.jwt.kid, issuer: config.jwtIssuer }, config.tls ? 'serving HTTPS' : 'serving plain HTTP, terminate TLS at a reverse proxy');
    this.maintenance.start();
    if (process.send) process.send('ready'); // PM2 wait_ready
  }

  /** @param {string} reason */
  async shutdown(reason) {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    const log = /** @type {import('./types.js').Logger} */ (this.app?.log ?? console);
    log.info({ reason }, 'shutting down');
    const forceExit = setTimeout(() => {
      log.error('shutdown timed out, exiting');
      process.exit(1);
    }, 30_000).unref();
    try {
      this.maintenance?.stop();
      await this.app?.close();
      await this.audit.close();
      this.db.close();
      clearTimeout(forceExit);
      log.info('shutdown complete');
      process.exit(0);
    } catch (err) {
      log.error({ err }, 'shutdown failed');
      process.exit(1);
    }
  }

  /** @param {import('./types.js').Logger} log */
  #installSignalHandlers(log) {
    process.on('SIGTERM', () => this.shutdown('SIGTERM'));
    process.on('SIGINT', () => this.shutdown('SIGINT'));
    process.on('unhandledRejection', (reason) => {
      log.fatal({ err: reason }, 'unhandled rejection');
      this.shutdown('unhandledRejection');
    });
    process.on('uncaughtException', (err) => {
      log.fatal({ err }, 'uncaught exception');
      process.exit(1);
    });
  }
}
