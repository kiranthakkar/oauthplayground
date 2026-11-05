# OAuth Playground

OAuth Playground is a loopback-only developer utility for exercising OAuth and OpenID Connect token flows against an authorization server. It serves one local HTML page and relays token requests; it is intended for test credentials only.

## Features

- Import authorization and token endpoints from an HTTPS OpenID configuration metadata URL.
- OIDC Authorization Code + PKCE, including state validation and a generated nonce.
- Optional OIDC refresh-token display and access-token renewal when `offline_access` is requested.
- OAuth 2.0 Client Credentials (2-legged).
- Delegated Authorization Code + PKCE with custom scopes and additional authorization parameters (3-legged).
- RFC 8693 ID token → ID-JAG token exchange.
- JWT-bearer ID-JAG token → Access token exchange.
- Per-flow token responses: switching tabs shows only that tab's most recent response.
- Access protected HTTPS resources with a GET request using the active flow's latest access token.
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

## Import provider endpoints

Paste the full `https://<issuer>/.well-known/openid-configuration` URL into **OpenID configuration URL** at the top of the page, then select **Import endpoints**. The local server fetches the document and validates its `authorization_endpoint` and `token_endpoint` before filling the corresponding fields across all flow tabs. The metadata URL and both endpoints must use HTTPS.

Imported endpoints remain editable. When a saved profile is selected, save that profile after importing so token exchanges use its updated endpoints. Importing does not require AgentSafe configuration.

## Flows and response display

| Tab | Flow | Response shown |
| --- | --- | --- |
| OIDC | Authorization Code + PKCE | ID token and Access token; Refresh token when `offline_access` was requested |
| 2-legged | Client Credentials | Access token |
| 3-legged | Custom Authorization Code + PKCE | Access token |
| ID token → ID-JAG token | RFC 8693 token exchange | ID-JAG token |
| ID-JAG token → Access token | JWT bearer grant | Access token |

The ID-JAG token exchange receives its result in the OAuth `access_token` field, but the UI correctly labels that result **ID-JAG token**. Each tab retains its own latest exchange result; tokens are never displayed in another tab's response panel.

Use **Clear** at the top right of the response panel to remove all token cards and refresh capability for the selected flow. Pending responses for that flow are discarded. Other flows retain their results; request traces have their own separate **Clear** control. The 2-legged Client Credentials form only needs the token endpoint, so it does not show an authorization endpoint field.

## OIDC refresh tokens

1. Configure the OIDC connection. **OIDC scopes** defaults to `openid offline_access urn:opc:idm:__myscopes__`; edit the scopes as needed for your provider.
2. Choose the provider-supported **Prompt** value and start sign-in. The playground sends exactly the selected value (`login` by default); **Provider default** omits `prompt`. It does not automatically append `consent` when `offline_access` is requested. If your provider requires explicit consent for offline access, select `consent`. The provider must enable offline access and the refresh-token grant for your client; requesting this scope does not guarantee issuance.
3. Exchange the authorization code. The response shows a **Refresh token** card only when the original sign-in requested `offline_access`. If the provider omitted the token, the card explains this and disables refresh.
4. Select **Refresh access token**. The playground sends `grant_type=refresh_token` through the local token relay using the original connection and client authentication. No additional sign-in is needed.

A successful refresh replaces the displayed access token. A rotated refresh token replaces the old one; when no replacement is returned, the existing refresh token remains available. An ID token returned on refresh replaces the displayed one; otherwise the original ID token remains, with an explanatory message. Failed refreshes show their error in the response panel and trace while retaining the current tokens for inspection or retry.

Tokens remain scoped to the OIDC flow. Changing the selected profile or form fields does not change the connection used by an existing refresh token. If that saved profile's endpoint or client ID is changed in storage, sign in again. Tokens are kept in browser memory and session traces, never saved in connection profiles. Reloading the page clears the refresh controls; complete a new sign-in to obtain another token. Copied traces follow the **Show secrets** setting and are redacted by default.

## Access protected resources

After a successful access-token exchange, **Access Protected Resource** appears below the token response. The resource endpoint defaults to `https://idcs-ff3532e3a9ba4bd7887f5cf49e2ae425.identity.oraclecloud.com/admin/v1/Users` and can be edited. Select **GET resource** to send a GET request with `Authorization: Bearer <access_token>` through the local server, then inspect the HTTP status and JSON or text response in that section. The provider controls whether the token's scopes and permissions allow access; 401/403 responses are displayed for inspection.

Each flow retains its own endpoint and resource result. New requests use that flow's latest access token, including a refreshed token. Clearing tokens hides the section; replacing or refreshing a token clears the previous resource result. Pending results cannot restore a cleared section or appear under another flow. The ID-JAG-only flow does not show resource controls; exchange the ID-JAG for an access token first.

The relay accepts HTTPS URLs only and does not follow redirects, so bearer tokens are sent only to the supplied endpoint. Responses are limited to 5 MiB. Resource bodies are displayed as text, with JSON formatted and the existing **Show secrets** redaction rules applied. Resource requests and responses stay in the browser's session trace and are not stored in saved profiles. No request is sent until **GET resource** is selected.

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

The active form's **Client authentication** selection applies to each token exchange, including saved-profile exchanges: **HTTP Basic** sends credentials in the Authorization header; **Request body** sends `client_id` and `client_secret` in the form body. For saved profiles, the relay retrieves the secret from encrypted storage. Changing the authentication selection does not require saving the profile again.

## Security notes

- Use test credentials only.
- Keep the server loopback-only.
- The browser keeps pending PKCE state and request traces in session storage.
- Traces redact secrets, tokens, authorization codes, PKCE verifiers, and nonces by default. The temporary **Show secrets** control overrides that redaction for the current browser session.
- Token responses are shown separately from traces so they can be copied or decoded locally.
