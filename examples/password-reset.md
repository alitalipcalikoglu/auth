# Forgot and reset password

## 1. Request a reset link

```bash
authcurl -X POST $AUTH/v1/auth/password/forgot -d '{ "email": "ali@example.com" }'
```

Always `202 {"accepted":true}`, even for unknown or disabled accounts, so the endpoint cannot be used to discover users. If the account exists, notify sends the `password-reset` template with `RESET_URL_TEMPLATE` filled in and the requester's IP (from `X-Client-IP`) shown in the mail.

Throttled per user by `RESEND_COOLDOWN_SEC`; a second request inside the window answers `429 TOO_MANY_REQUESTS`.

## 2. Reset

The user lands on your frontend with `?token=…` and types a new password. Your backend calls:

```bash
authcurl -X POST $AUTH/v1/auth/password/reset -d '{ "token": "Zx9k…", "password": "a brand new strong password" }'
```

`200` with the user. Side effects:

- every session of the user is revoked (all devices logged out)
- the email is marked verified (the user proved they own the mailbox)
- `password.reset` is recorded in the audit log

## Weak password does not burn the link

```bash
authcurl -X POST $AUTH/v1/auth/password/reset -d '{ "token": "Zx9k…", "password": "short" }'
```

`400 WEAK_PASSWORD` and the token stays valid, so the user can try again with a better password. Only a successful reset consumes it.

## Expired or used link

`401 INVALID_TOKEN` "reset link is invalid or expired". Tokens last `RESET_TOKEN_TTL_MIN` (default 60). Requesting a new link invalidates any earlier one.
