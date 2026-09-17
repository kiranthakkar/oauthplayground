# OAuth Playground contributor guide

## Project shape

This is a local, loopback-only OAuth test utility. It has no build step:

- `index.html` contains the entire UI, styles, and browser-side behavior.
- `server.py` serves the UI and relays token requests to HTTPS token endpoints.
- `requirements.txt` pins `agentconfigsafe[oci]` for encrypted profile storage.

Run it with the virtual environment that contains the pinned dependency:

```sh
python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt
venv/bin/python server.py
```

## Supported flows

| Flow key | UI flow | Expected response cards |
| --- | --- | --- |
| `oidc` | Authorization Code + PKCE | ID token and Access token |
| `twoleg` | Client Credentials | Access token only |
| `threeleg` | Custom Authorization Code + PKCE | Access token only |
| `idjag` | ID token → ID-JAG token (RFC 8693) | ID-JAG token only; it is returned in `access_token` |
| `jagaccess` | ID-JAG token → Access token (JWT bearer) | Access token only |

## Browser-state requirements

- Token responses are scoped to a flow key in `tokenResultsByFlow`; never reuse a token from another tab.
- Switching tabs must immediately re-render the response panel for the selected flow. Hide it when that flow has no result.
- An exchange records the flow that initiated it before the network request, so changing tabs during an in-flight request cannot misfile its response.
- OIDC keeps both token cards. Every other flow hides the ID-token card. The `idjag` flow relabels the `access_token` card to **ID-JAG token**.
- Token display/copy controls operate on the active flow's latest result. JWT decoding is local only and does not verify a signature.
- Request traces live only in browser session storage and redact secrets, tokens, authorization codes, PKCE verifiers, and nonces unless the user explicitly enables the reveal control.
- Trace redaction matches on key name (`secret`, `token`, `authorization`, `verifier`, `code`, `nonce`). Keys ending in `Endpoint` (e.g. `tokenEndpoint`, `authorizationEndpoint`) are configuration URLs, not secret values, and must stay visible in the trace even though their names contain a matched substring.

## Profile-storage requirements

- `profiles.json` stores metadata only: profile ID, display name, and update timestamp.
- The saved connection fields—authorization endpoint, token endpoint, client ID, client secret, and redirect URI—are an OCI KMS-encrypted JSON blob in `appconfig` under `oauth-profile:<profile-id>`.
- Never return a client secret from the profiles API. A blank secret in the edit form means retain the saved secret.
- AgentSafe configuration is project-local at `.agentsafe/config` and requires `profile`, `crypto_endpoint`, and `key_id`. Do not add a `compartment` or application-name requirement; the pinned AgentSafe CLI does not support them.
- If configured AgentSafe has no `appconfig`, `PlaygroundHandler.safe()` must create a secure empty store before reads. Do not treat an absent store as uninitialized.
- Preserve the legacy migration guarantee: encrypt every legacy profile configuration successfully before removing its plaintext fields from `profiles.json`.
- When AgentSafe itself is unconfigured or unavailable, unsaved one-time flows remain usable; saved-profile endpoints return their clear failure response and must not fall back to plaintext storage.

## Safety and implementation rules

- Keep the server bound to `127.0.0.1` and require `https://` token endpoints.
- The HTTP server serves only the app shell (`/`, `/index.html`) and the defined `/api/*` routes. Never let static-file serving fall through to other project files (`server.py`, `profiles.json`, `appconfig`, `.agentsafe/`, `requirements.txt`, `venv/`, docs) — those must 404.
- Use test credentials only. Do not log decrypted values or tokens.
- Preserve callback state validation and the rule that an authorization error is never exchangeable.
- Keep response error bodies visible only in the response panel/trace, subject to existing redaction behavior.

## Verification

There is no automated test suite. At minimum after UI edits, validate inline JavaScript syntax:

```sh
node -e "const fs=require('fs'); const html=fs.readFileSync('index.html','utf8'); [...html.matchAll(/<script>([\\s\\S]*?)<\\/script>/g)].forEach((match) => new Function(match[1]));"
```

After server edits, run:

```sh
venv/bin/python -m py_compile server.py
```

After server edits, also confirm the static-file allowlist holds — each of these must print `404`:

```sh
for f in server.py profiles.json appconfig .agentsafe/config requirements.txt; do
  curl -s -o /dev/null -w "%{http_code} $f\n" "http://127.0.0.1:5177/$f"
done
```

For AgentSafe bootstrap changes, verify a missing store is created in a disposable directory and has `0600` permissions.
