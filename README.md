# auth

Authentication service for application backends: user accounts, scrypt passwords, short-lived ES256 access tokens, rotating refresh tokens with reuse detection, email verification and password reset, audit log. Talks to other services over HTTP only; sends email through the [notify](https://github.com/alitalipcalikoglu/notify) service.

Runtime dependencies: `fastify`, `@fastify/rate-limit`, `jose`. Storage is SQLite via `node:sqlite` (built into Node 22.13+). The folder is self-contained: copy it to any host with Node 22 and run.

## Run

```bash
cp .env.example .env        # fill in keys, issuer, notify settings
npm ci
npm run keygen              # writes keys/jwt-private.pem and keys/jwt-public.pem
npm run dev
```

Production with PM2 (reads `./.env` through Node's `--env-file`):

```bash
npm ci --omit=dev
pm2 start ecosystem.config.cjs
pm2 save && pm2 startup
```

Production with Docker (mount the database and key directories):

```bash
docker build -t atc-auth .
docker run -p 3002:3002 -v auth-data:/data -v ./keys:/keys:ro --env-file .env atc-auth
```

Tests and type check:

```bash
npm test
npm run typecheck
```

## Model

- **Callers are trusted backends.** Every `/v1` request carries `Authorization: Bearer <API key>` from `AUTH_API_KEYS`. Browsers never talk to this service directly; your backend does, and forwards the end user's address in `X-Client-IP` and agent in `X-Client-User-Agent` for the audit log.
- **Access token**: JWT, ES256, `ACCESS_TOKEN_TTL_SEC` (default 15 min). Claims: `iss`, `aud`, `sub` (user id), `sid` (session id), `email`, `email_verified`, `iat`, `exp`, `jti`. Other services verify it locally with `GET /.well-known/jwks.json`, no call to auth needed. Use `POST /v1/auth/introspect` when you also need to know that the session has not been revoked.
- **Refresh token**: opaque 256-bit secret, stored hashed, `REFRESH_TOKEN_TTL_DAYS` absolute lifetime. Each refresh rotates it. Presenting an already-rotated token revokes the whole session (`TOKEN_REUSED`).
- **One-time links** for verification and reset are opaque tokens that expire and are single use. The service never builds pages; it puts `{token}` into `VERIFY_URL_TEMPLATE` / `RESET_URL_TEMPLATE`, which point at your frontend, and your backend forwards the token here.

## API

Errors are JSON: `{ "error": { "code", "message", "details?" } }`. `423` and `429` carry `Retry-After`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health`, `/ready` | Liveness; readiness (database + notify reachable, cached 30 s). No auth. |
| GET | `/.well-known/jwks.json` | Public keys for local JWT verification. No auth. |
| POST | `/v1/users` | Register `{ email, password, name? }`. `201` with `user` and `verificationEmailSent`. |
| GET | `/v1/users` | List (`limit`, `cursor`) or look up `?email=`. |
| GET / PATCH / DELETE | `/v1/users/:id` | Read; update `{ name?, status? }` (disabling revokes sessions); hard delete. |
| GET / DELETE | `/v1/users/:id/sessions` | Active sessions; revoke all. |
| DELETE | `/v1/users/:id/sessions/:sid` | Revoke one session. |
| GET | `/v1/users/:id/events` | Audit log, newest first (`limit`, `before`). |
| POST | `/v1/auth/login` | `{ email, password }` → `{ user, tokens }`. |
| POST | `/v1/auth/refresh` | `{ refreshToken }` → new `{ user, tokens }`. |
| POST | `/v1/auth/logout` | `{ refreshToken }` → `204`. Idempotent. |
| POST | `/v1/auth/introspect` | `{ accessToken }` → `{ active, claims?, reason? }`. |
| POST | `/v1/auth/verify-email` | `{ token }` → `{ user }`. |
| POST | `/v1/auth/verify-email/resend` | `{ email }` → `202`. Silent for unknown emails, throttled per user. |
| POST | `/v1/auth/password/forgot` | `{ email }` → `202`. Always accepted. |
| POST | `/v1/auth/password/reset` | `{ token, password }` → `{ user }`. Revokes all sessions, marks email verified. |
| POST | `/v1/auth/password/change` | Header `X-Access-Token: <jwt>`, body `{ currentPassword, newPassword }` → `204`. Keeps the current session, revokes the others. |
| GET | `/metrics` | Prometheus text: users by status, active sessions, uptime. API key required. |

Error codes: `EMAIL_TAKEN`, `WEAK_PASSWORD`, `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `ACCOUNT_DISABLED`, `EMAIL_NOT_VERIFIED`, `INVALID_TOKEN`, `TOKEN_REUSED`, `USER_NOT_FOUND`, `SESSION_NOT_FOUND`, `ALREADY_VERIFIED`, `TOO_MANY_REQUESTS`, `RATE_LIMITED`, `VALIDATION_FAILED`, `UNAUTHORIZED`.

### Typical flow from your backend

1. `POST /v1/users` with the sign-up form. Show "check your inbox".
2. User clicks the link in the email, lands on your frontend, which posts the token to your backend; your backend calls `POST /v1/auth/verify-email`.
3. `POST /v1/auth/login`; hand the access token to the client, keep the refresh token in an httpOnly cookie or secure storage.
4. Verify access tokens locally with the JWKS on every request. Refresh through `POST /v1/auth/refresh` before expiry.
5. On logout call `POST /v1/auth/logout` with the refresh token.

### Verifying tokens in another Node service

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';
const jwks = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));
const { payload } = await jwtVerify(token, jwks, { issuer: 'https://auth.example.com', audience: 'shop' });
```

## Examples

Scenario walkthroughs for every feature live in [examples/](examples/README.md).

## Configuration

All settings come from environment variables and are validated at startup. See [.env.example](.env.example).

Required: `AUTH_API_KEYS`, `JWT_PRIVATE_KEY_PATH`, `JWT_ISSUER`, `JWT_AUDIENCE`, `NOTIFY_URL`, `NOTIFY_API_KEY`, `APP_NAME`, `VERIFY_URL_TEMPLATE`, `RESET_URL_TEMPLATE`.

Key rotation: run `npm run keygen -- keys/jwt-2027`, point `JWT_PRIVATE_KEY_PATH` at the new private key and `JWT_PREVIOUS_PUBLIC_KEY_PATH` at the old public key, restart. Tokens signed by the old key stay valid until they expire; JWKS publishes both. Remove the previous key after `ACCESS_TOKEN_TTL_SEC` has passed.

## Security notes

- Passwords: scrypt (`SCRYPT_LOG_N`, default 2^15, r=8, p=1), 32-byte salt, NFKC normalised. Hashes are upgraded transparently at next login when the cost is raised. Policy: minimum length, common-password denylist including "word + digits" variants, no email-derived passwords.
- Login: constant-time hash comparison; unknown emails cost the same as a wrong password; lockout after `LOGIN_MAX_FAILURES` for `LOGIN_LOCKOUT_MIN`. Optional `LOGIN_REQUIRES_VERIFIED_EMAIL`.
- Tokens: only SHA-256 hashes of refresh, verification and reset tokens are stored. Reset validates the new password before spending the link. Reset revokes all sessions; password change revokes all other sessions.
- API keys compared in constant time; per-key rate limit; request bodies capped at `BODY_LIMIT`; unknown fields rejected; `Cache-Control: no-store` on every response except JWKS.
- Enumeration resistance: `forgot` and `resend` return `202` whether or not the email exists.
- Audit log: registration, verification, login success/failure with reason, lockout, refresh, reuse detection, logout, password events, session and account changes. Retained `EVENT_RETENTION_DAYS`.
- Container runs as the unprivileged `node` user; keys mounted read-only.

## Code layout

Class-based; dependencies are injected through constructors, `src/application.js` is the composition root.

| Class | File | Role |
|---|---|---|
| `Application` | `src/application.js` | Wiring, startup, graceful shutdown |
| `Config` | `src/config.js` | Validated environment |
| `Database` | `src/db.js` | SQLite connection, migrations, transactions |
| `PasswordHasher`, `OpaqueToken`, `JwtSigner` | `src/crypto/` | Hashing, random secrets, ES256 JWT + JWKS |
| `UserStore`, `SessionStore`, `ActionTokenStore`, `EventStore` | `src/store/` | Persistence |
| `AuthService` | `src/domain/auth-service.js` | All use-cases |
| `PasswordPolicy`, `AuthError`, `Mailer` → `NotifyMailer` | `src/domain/` | Rules, errors, outbound mail |
| `AuthApi`, `ApiKeyAuth`, `Schemas`, `Views` | `src/http/` | Fastify routes and shapes |
| `Maintenance` | `src/maintenance.js` | Hourly retention purge |
| `KeyGenerator` | `scripts/keygen.js` | Signing key pair |

## Out of scope by design

- Social login (OAuth/OIDC providers), multi-factor authentication, roles and permissions: add as separate modules when a product needs them; the session and audit model already supports them.
- Multi-tenant user pools: one deployment serves one user pool. Run another instance for another product.
- Multiple processes on one SQLite file: intended deployment is one instance per database.

## Audit events

With `AUDIT_URL` and `AUDIT_API_KEY` set, every security event this service records per user (registration, verification, login success and failure with the reason, lockout, refresh, logout, session revocation, password reset and change, account disable/enable/delete) is also forwarded to the audit service as `auth.<event type>` with the user as actor and target, the client IP and the event's metadata. Attempts that did not succeed carry `outcome: "failure"`. Forwarding is buffered and never slows down or fails a request. Details: [examples/audit-events.md](examples/audit-events.md).

## Scaling model

Single-node stateful: one process, one SQLite file. `UNIQUE` constraints (email, token hashes) keep
the data correct under concurrent requests within that process; two processes against the same
file is not the supported or tested deployment model.

## Observability

Accepts an inbound `X-Request-Id` unconditionally and logs it via Fastify's default request
logging. Does not parse or forward `traceparent`. The security events this service forwards to
audit do not yet carry a request id of their own — only auth's own log line for the causing request
does.

## Backup / restore

Back up the database and the JWT signing key files (`keys/`) together; restoring the database with
a different signing key invalidates every outstanding access token immediately. `stack backup`/
`stack restore` from the workspace root (see `stack/docs/UPGRADE.md`) captures the database and
`keys/` together for exactly this reason. On every start, before applying a pending migration to an
existing database, the service itself also snapshots the database file to
`DB_PATH.pre-v<N>-<timestamp>` (directory overridable with `DB_BACKUP_DIR`) — a manual last resort
that still needs `keys/` restored alongside it.

**Rollback limitations:** none of the migrations are reversible; to roll back, restore the database
and `keys/` from the same `stack backup` snapshot (or the pre-migration database copy plus a
same-time copy of `keys/`) and run the previous version of this service against it.

See [docs/READINESS.md](docs/READINESS.md) for the full contract.

## License

MIT, see [LICENSE](LICENSE).
