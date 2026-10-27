# Next-gen signing service authentication

The v1 protocol supports the registered-key profile used by Heidi. Registration
state, replay protection, keys, and grants are held in process memory.

Registered mode requires an allow-list of client public keys, encoded as
standard Base64 in a JSON object:

```sh
SIGNING_AUTH_MODE=registered
SIGNING_AUTH_CLIENT_ACCEPTANCE=allow-list
SIGNING_AUTH_CLIENT_ADMINISTRATOR=platform
SIGNING_AUTH_CLIENTS='{"issuer":"<base64-ed25519-public-key>","platform":"<base64-ed25519-public-key>"}'
```

Use the public key derived for provider scheme `next-gen`. The seed stays in
each Heidi client. Empty client configuration is rejected in registered mode.
Platform-assisted acceptance can add clients through the authenticated
`/v1/auth/clients` endpoint; the platform administrator key must still be
allow-listed.

`SIGNING_AUTH_MODE=none` preserves the legacy unauthenticated behavior and is
the default for existing local deployments. Production deployments should set
registered mode and supply an allow-list.
