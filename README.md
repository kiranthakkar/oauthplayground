# OAuth Playground

OAuth Playground is a loopback-only developer utility for exercising OAuth and OpenID Connect token flows against an authorization server. It serves one local HTML page and relays token requests; it is intended for test credentials only.

## Features

- OIDC Authorization Code + PKCE, including state and nonce validation.
- OAuth 2.0 Client Credentials (2-legged).
- Delegated Authorization Code + PKCE with custom scopes and additional authorization parameters (3-legged).
- RFC 8693 ID token → ID-JAG token exchange.
- JWT-bearer ID-JAG token → Access token exchange.
- Per-flow token responses: switching tabs shows only that tab's most recent response.
- Local encoded-token copy and optional JWT payload/header decoding. Decoding does not verify signatures.
- Session-only request trace with sensitive fields redacted by default.
- Encrypted saved connection profiles using OCI KMS through AgentSafe.

## Run locally

Python 3.10+ is required.

```sh
python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt
venv/bin/python server.py
```

Open [http://localhost:5177](http://localhost:5177). For authorization-code flows, register that exact URL as a redirect URI with the test identity provider. The server listens only on `127.0.0.1`; token endpoints must use HTTPS.

## Flows and response display

| Tab | Flow | Response shown |
| --- | --- | --- |
| OIDC | Authorization Code + PKCE | ID token and Access token |
| 2-legged | Client Credentials | Access token |
| 3-legged | Custom Authorization Code + PKCE | Access token |
| ID token → ID-JAG token | RFC 8693 token exchange | ID-JAG token |
| ID-JAG token → Access token | JWT bearer grant | Access token |

The ID-JAG token exchange receives its result in the OAuth `access_token` field, but the UI correctly labels that result **ID-JAG token**. Each tab retains its own latest exchange result; tokens are never displayed in another tab's response panel.

## Encrypted profiles

Profiles are optional. Without AgentSafe, one-time unsaved flows still work, but saving, loading, and deleting profiles is unavailable.

Configure AgentSafe once from the project directory with an OCI Vault key your local OCI profile can use:

```sh
agentsafe init --profile DEFAULT \
  --crypto-endpoint <vault-crypto-url> \
  --key-id <key-ocid>
```

This writes the project-local KMS configuration to `.agentsafe/config`. The playground validates `profile`, `crypto_endpoint`, and `key_id`. When this configuration is valid and `appconfig` does not exist yet, the server automatically creates an empty encrypted-store file with owner-only permissions.

`profiles.json` contains only profile metadata (ID, name, and timestamp). The authorization endpoint, token endpoint, client ID, client secret, and redirect URI are stored together as an OCI KMS-encrypted blob in `appconfig`, keyed as `oauth-profile:<profile-id>`. Client secrets are never returned to the browser. Existing plaintext legacy profile data is migrated only after encryption succeeds.

## Security notes

- Use test credentials only.
- Keep the server loopback-only.
- The browser keeps pending PKCE state and request traces in session storage.
- Traces redact secrets, tokens, authorization codes, PKCE verifiers, and nonces by default. The temporary **Show secrets** control overrides that redaction for the current browser session.
- Token responses are shown separately from traces so they can be copied or decoded locally.
