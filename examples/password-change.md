# Change password

Scenario: a signed-in user changes their password from the account page.

The user is identified by their **access token**, sent in `X-Access-Token`. `Authorization` still carries your backend's API key.

```bash
authcurl -X POST $AUTH/v1/auth/password/change \
  -H "X-Access-Token: eyJhbGciOiJFUzI1NiIs…" \
  -d '{ "currentPassword": "correct horse battery staple", "newPassword": "even longer and stronger phrase" }'
```

`204`. The session that made the change keeps working (its refresh token stays valid); every other session of the user is revoked, so a stolen device is logged out.

## Errors

| Status | Code | When |
|---|---|---|
| 401 | `INVALID_TOKEN` | `X-Access-Token` missing, expired, or its session revoked |
| 401 | `INVALID_CREDENTIALS` | `currentPassword` wrong (`password.change_failed` is logged) |
| 400 | `WEAK_PASSWORD` | New password rejected by the policy |

## Why not a refresh token here

Access tokens are what the browser already holds, expire fast, and identify the session (`sid`), which is exactly what is needed to keep this one session alive while revoking the rest.
