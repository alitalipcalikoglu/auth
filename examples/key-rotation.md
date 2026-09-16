# Signing key rotation

Access tokens are signed with an ES256 key pair. Rotate it yearly or after any suspicion of leakage, without invalidating live tokens.

## 1. Generate the new pair

```bash
npm run keygen -- keys/jwt-2027
# private key: keys/jwt-2027-private.pem
# public key:  keys/jwt-2027-public.pem
```

The generator refuses to overwrite existing files; the private key is written with mode `0600`.

## 2. Switch, keeping the old public key

```
JWT_PRIVATE_KEY_PATH=./keys/jwt-2027-private.pem
JWT_PREVIOUS_PUBLIC_KEY_PATH=./keys/jwt-2026-public.pem
```

```bash
pm2 reload auth
```

New logins are signed with the 2027 key. Tokens signed with the 2026 key still verify, and `/.well-known/jwks.json` publishes both keys with their `kid`, so services verifying locally keep working (jose refreshes the JWKS when it meets an unknown `kid`).

```bash
curl -s $AUTH/.well-known/jwks.json | jq '.keys[].kid'
```

## 3. Retire the old key

After `ACCESS_TOKEN_TTL_SEC` (15 min by default) no token signed with the old key can still be valid. Remove `JWT_PREVIOUS_PUBLIC_KEY_PATH`, reload, delete the old private key.

## Emergency: key compromised

Skip step 2's overlap: set only the new private key, reload. Every outstanding access token becomes invalid immediately (`UNKNOWN_KEY`); refresh tokens are unaffected, so clients recover on their next refresh without re-entering passwords.
