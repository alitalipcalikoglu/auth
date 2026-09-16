# Refresh, logout and reuse detection

## Refresh before the access token expires

```bash
authcurl -X POST $AUTH/v1/auth/refresh -d '{ "refreshToken": "c1Yt8bZ…" }'
```

`200` with a **new** access token and a **new** refresh token in the same `sessionId`. Store the new refresh token; the old one is now invalid.

## Replay of an old refresh token

If the old token is presented again:

```json
HTTP/1.1 401
{ "error": { "code": "TOKEN_REUSED", "message": "refresh token was already used; session revoked" } }
```

The whole session is revoked, including the token that was handed out on the last legitimate refresh. Reasoning: either the client lost a response and will simply log in again, or someone stole the token; in both cases ending the session is the safe move. The event `session.reuse_detected` lands in the audit log.

After that, the newest token also fails:

```json
{ "error": { "code": "INVALID_TOKEN", "message": "session has been revoked" } }
```

## Logout

```bash
authcurl -X POST $AUTH/v1/auth/logout -d '{ "refreshToken": "c1Yt8bZ…" }'
```

`204`. Idempotent: unknown or already revoked tokens also return `204`. Access tokens issued for that session stay cryptographically valid until `exp`; introspection reports them `SESSION_REVOKED` immediately.

## Refresh token lifetime

Absolute: `REFRESH_TOKEN_TTL_DAYS` (default 30) from login, not extended by refreshes. After that: `401 INVALID_TOKEN` "session expired". Ask the user to log in again.

## Other reasons a refresh fails

| Code | Meaning |
|---|---|
| `INVALID_TOKEN` | Unknown token, revoked or expired session |
| `TOKEN_REUSED` | Old token replayed; session revoked |
| `ACCOUNT_DISABLED` | User disabled since login; session revoked |

## Client pattern

```
try request with access token
  on 401 → POST /v1/auth/refresh with the stored refresh token
     on 200 → store both new tokens, retry the request once
     on 401 → clear tokens, show login
```
