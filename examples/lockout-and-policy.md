# Lockout and password policy

## Brute-force lockout

After `LOGIN_MAX_FAILURES` (default 10) wrong passwords the account is locked for `LOGIN_LOCKOUT_MIN` (default 15):

```bash
for i in $(seq 1 10); do authcurl -X POST $AUTH/v1/auth/login -d '{"email":"ali@example.com","password":"nope"}' -o /dev/null -w '%{http_code} '; done
# 401 401 401 401 401 401 401 401 401 401
authcurl -X POST $AUTH/v1/auth/login -d '{"email":"ali@example.com","password":"correct horse battery staple"}' -i
```

```
HTTP/1.1 423 Locked
Retry-After: 897
{ "error": { "code": "ACCOUNT_LOCKED", "message": "too many failed attempts, try again later", "details": { "retryAfterSec": 897 } } }
```

The correct password is refused too while locked. A successful login after the window resets the counter. `lockedUntil` is visible on `GET /v1/users/:id`. Audit log: `login.failed` with `reason: bad_password` and `failures`, then `account.locked`.

Unknown emails are never locked (there is nothing to lock) but cost the same CPU as a real check.

## Password policy

Checked on registration, reset and change. Configurable minimum: `PASSWORD_MIN_LENGTH` (default 10). Fixed rules:

| Rejected | Example | Message |
|---|---|---|
| too short | `abc123` | `must be at least 10 characters` |
| too long | > 256 chars | `must be at most 256 characters` |
| common password, also with digits/symbols appended | `password1234`, `Qwerty2024!` | `is too common` |
| one repeated character | `aaaaaaaaaaaa` | `must not repeat a single character` |
| contains the email or its local part | `alitalip2024!` for `alitalip@…` | `must not contain your email address` |
| leading/trailing whitespace | `" secret words "` | `must not start or end with whitespace` |

All problems are returned at once:

```json
{ "error": { "code": "WEAK_PASSWORD", "message": "password must be at least 10 characters; is too common",
  "details": { "problems": ["must be at least 10 characters", "is too common"] } } }
```

Passwords are NFKC-normalised before hashing, so `ﬁsh` and `fish` are the same password.

## Hash cost

scrypt with `N = 2^SCRYPT_LOG_N` (default 15, about 100 ms per check). Raising the value later is safe: existing users are re-hashed transparently on their next successful login.
