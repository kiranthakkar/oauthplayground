#!/usr/bin/env python3
"""Local OAuth token relay with OCI KMS-encrypted profile configuration."""

import base64
import json
import os
from datetime import UTC, datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from agentsafe import AgentSafe, AgentSafeError, KeyNotFoundError

ROOT = Path(__file__).parent
PROFILES_FILE = ROOT / "profiles.json"
SECRETS_FILE = ROOT / "appconfig"
PORT = int(os.environ.get("PORT", "5177"))
PROFILE_SCHEMA_VERSION = 2
METADATA_KEYS = {"id", "name", "updatedAt"}
PROFILE_CONFIG_KEYS = {
    "authorizationEndpoint",
    "tokenEndpoint",
    "clientId",
    "clientSecret",
    "redirectUri",
}
REQUIRED_AGENTSAFE_SETTINGS = ("profile", "crypto_endpoint", "key_id")


class SecretStoreNotInitialized(AgentSafeError):
    """Raised before an OCI KMS operation when AgentSafe has no usable configuration."""


def now():
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class PlaygroundHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    @staticmethod
    def config_key(profile_id):
        """Deterministic: one encrypted configuration blob for each profile ID."""
        return f"oauth-profile:{profile_id}"

    @staticmethod
    def legacy_secret_key(profile_id):
        return f"oauth-profile:{profile_id}:client-secret"

    @staticmethod
    def ensure_agent_safe_store_schema():
        """Repair only the legacy empty ``{}`` store shape before AgentSafe uses it."""
        if not SECRETS_FILE.exists():
            return
        try:
            document = json.loads(SECRETS_FILE.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise SecretStoreNotInitialized(
                "AgentSafe appconfig is unreadable; it was not changed."
            ) from error
        if document == {}:
            temporary = SECRETS_FILE.with_suffix(".tmp")
            temporary.write_text(json.dumps({"schema_version": 1, "entries": {}}, indent=2) + "\n")
            os.chmod(temporary, 0o600)
            temporary.replace(SECRETS_FILE)
            os.chmod(SECRETS_FILE, 0o600)
        elif not isinstance(document, dict) or not isinstance(document.get("entries"), dict):
            raise SecretStoreNotInitialized(
                "AgentSafe appconfig has an unsupported format; it was not changed."
            )

    def safe(self):
        self.ensure_agent_safe_store_schema()
        safe = AgentSafe(SECRETS_FILE)
        missing = [key for key in REQUIRED_AGENTSAFE_SETTINGS if not safe.settings.get(key)]
        if missing:
            raise SecretStoreNotInitialized(
                "AgentSafe is not initialized. "
                "Run: agentsafe init --profile DEFAULT "
                "--crypto-endpoint <vault-crypto-url> "
                "--key-id <key-ocid>"
            )
        # AgentSafe creates appconfig lazily on the first write, but this
        # playground reads profiles before it writes one. Bootstrap the empty
        # encrypted store once configuration has been validated.
        safe.store.ensure_initialized()
        return safe

    def profiles(self):
        if not PROFILES_FILE.exists():
            return []
        try:
            document = json.loads(PROFILES_FILE.read_text())
        except json.JSONDecodeError:
            return []
        # Read legacy top-level arrays so they can be migrated safely.
        if isinstance(document, list):
            return document
        profiles = document.get("profiles", []) if isinstance(document, dict) else []
        return profiles if isinstance(profiles, list) else []

    def save_profiles(self, profiles):
        document = {"schemaVersion": PROFILE_SCHEMA_VERSION, "profiles": profiles}
        temporary = PROFILES_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(document, indent=2) + "\n")
        os.chmod(temporary, 0o600)
        temporary.replace(PROFILES_FILE)
        os.chmod(PROFILES_FILE, 0o600)

    @staticmethod
    def metadata(profile):
        return {key: profile[key] for key in METADATA_KEYS if key in profile}

    def read_config(self, profile_id):
        try:
            raw = self.safe().get(self.config_key(profile_id))
        except KeyNotFoundError:
            raise ValueError("No encrypted configuration exists for this profile.") from None
        try:
            config = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("The encrypted profile configuration is invalid.") from None
        if not isinstance(config, dict):
            raise ValueError("The encrypted profile configuration is invalid.")
        return config

    def migrate_legacy_profiles(self, profiles):
        """Encrypt v1 profile fields as one blob before deleting them from profiles.json."""
        legacy = [profile for profile in profiles if set(profile) - METADATA_KEYS]
        if not legacy:
            return profiles
        safe = self.safe()
        migrated, old_keys = [], []
        for profile in profiles:
            if not (set(profile) - METADATA_KEYS):
                migrated.append(profile)
                continue
            profile_id = profile.get("id")
            if not profile_id:
                raise ValueError("A legacy profile is missing its ID.")
            config = {key: value for key, value in profile.items() if key in PROFILE_CONFIG_KEYS}
            if not config.get("clientSecret"):
                try:
                    config["clientSecret"] = safe.get(self.legacy_secret_key(profile_id))
                    old_keys.append(self.legacy_secret_key(profile_id))
                except KeyNotFoundError:
                    pass
            safe.set(self.config_key(profile_id), json.dumps(config))
            migrated.append({**self.metadata(profile), "updatedAt": profile.get("updatedAt") or now()})
        # Only remove legacy plaintext after every replacement blob was encrypted.
        self.save_profiles(migrated)
        for key in old_keys:
            try:
                safe.remove(key)
            except KeyNotFoundError:
                pass
        return migrated

    def public_profiles(self):
        profiles = self.migrate_legacy_profiles(self.profiles())
        result = []
        for profile in profiles:
            try:
                stored_config = self.read_config(profile["id"])
            except ValueError:
                # Keep an orphaned profile selectable so saving it can recreate
                # its encrypted configuration rather than breaking every profile.
                result.append({**profile, "hasClientSecret": False, "configurationUnavailable": True})
                continue
            config = {key: value for key, value in stored_config.items() if key in PROFILE_CONFIG_KEYS}
            if config != stored_config:
                self.safe().set(self.config_key(profile["id"]), json.dumps(config))
            has_secret = bool(config.pop("clientSecret", ""))
            result.append({**profile, **{key: value for key, value in config.items() if key in PROFILE_CONFIG_KEYS}, "hasClientSecret": has_secret})
        return result

    def save_profile(self, incoming):
        if not incoming.get("id") or not incoming.get("name"):
            raise ValueError("A profile name is required.")
        profiles = self.migrate_legacy_profiles(self.profiles())
        existing = next((profile for profile in profiles if profile.get("id") == incoming["id"]), None)
        config = {key: value for key, value in incoming.items() if key in PROFILE_CONFIG_KEYS}
        # A blank browser field means retain—not erase—the stored secret.
        if not config.get("clientSecret") and existing:
            try:
                config["clientSecret"] = self.read_config(existing["id"]).get("clientSecret", "")
            except ValueError:
                # The metadata may outlive a lost/corrupt encrypted blob. Saving
                # the form recreates it; no secret can be recovered or inferred.
                pass
        self.safe().set(self.config_key(incoming["id"]), json.dumps(config))
        record = {"id": incoming["id"], "name": incoming["name"], "updatedAt": now()}
        self.save_profiles([profile for profile in profiles if profile.get("id") != record["id"]] + [record])
        return {**record, **{key: value for key, value in config.items() if key != "clientSecret"}, "hasClientSecret": bool(config.get("clientSecret"))}

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/secrets-status":
            try:
                self.safe()
                return self.send_json(200, {"ready": True})
            except SecretStoreNotInitialized as error:
                return self.send_json(503, {"ready": False, "code": "secrets_not_initialized", "error": str(error)})
            except AgentSafeError as error:
                return self.send_json(503, {"ready": False, "code": "secrets_unavailable", "error": str(error)})
        if path == "/api/profiles":
            try:
                return self.send_json(200, self.public_profiles())
            except SecretStoreNotInitialized as error:
                return self.send_json(503, {"code": "secrets_not_initialized", "error": str(error)})
            except (AgentSafeError, ValueError) as error:
                return self.send_json(503, {"error": f"Encrypted profile store is unavailable: {error}"})
        # Static serving is intentionally limited to the app shell. Everything
        # else in the project root (server.py, profiles.json, appconfig,
        # .agentsafe/, venv/, docs) must never be reachable over HTTP.
        if path not in ("/", "/index.html"):
            return self.send_json(404, {"error": "Not found"})
        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/profiles":
            try:
                return self.send_json(200, self.save_profile(self.read_body()))
            except SecretStoreNotInitialized as error:
                return self.send_json(503, {"code": "secrets_not_initialized", "error": str(error)})
            except (ValueError, json.JSONDecodeError, AgentSafeError) as error:
                return self.send_json(400, {"error": str(error)})
        if self.path not in {
            "/api/token",
            "/api/id-token-to-id-jag",
            "/api/id-jag-to-access-token",
        }:
            return self.send_json(404, {"error": "Not found"})
        try:
            payload = self.read_body()
            profile_id = payload.get("profileId", "")
            config = self.read_config(profile_id) if profile_id else payload
            endpoint = config.get("tokenEndpoint", "")
            if not endpoint.startswith("https://"):
                raise ValueError("A HTTPS token endpoint is required.")
            if self.path == "/api/id-token-to-id-jag":
                id_token = payload.get("idToken", "")
                if not isinstance(id_token, str) or not id_token:
                    raise ValueError("An ID token is required for ID-JAG token exchange.")
                params = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                    "subject_token": id_token,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                    "scope": payload.get("scope", ""),
                    "resource": payload.get("resource", ""),
                }
            elif self.path == "/api/id-jag-to-access-token":
                id_jag_token = payload.get("idJagToken", "")
                if not isinstance(id_jag_token, str) or not id_jag_token:
                    raise ValueError("An ID-JAG token is required for access token exchange.")
                params = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": id_jag_token,
                    "scope": payload.get("scope", ""),
                }
            else:
                params = dict(payload.get("params", {}))
            client_id, secret = config.get("clientId", ""), config.get("clientSecret", "")
            headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
            client_auth = config.get("clientAuth", "basic")
            if client_auth == "basic" and secret:
                credential = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
                headers["Authorization"] = f"Basic {credential}"
            elif client_id:
                params["client_id"] = client_id
            if client_auth != "basic" and secret:
                params["client_secret"] = secret
            request = Request(endpoint, data=urlencode(params).encode(), headers=headers, method="POST")
            with urlopen(request, timeout=30) as response:
                body, status = response.read().decode("utf-8"), response.status
            try:
                result = json.loads(body)
            except json.JSONDecodeError:
                result = {"raw": body}
            self.send_json(status, result)
        except HTTPError as error:
            body = error.read().decode("utf-8")
            try:
                result = json.loads(body)
            except json.JSONDecodeError:
                result = {"raw": body}
            self.send_json(error.code, result)
        except SecretStoreNotInitialized as error:
            self.send_json(503, {"code": "secrets_not_initialized", "error": str(error)})
        except (ValueError, json.JSONDecodeError, URLError, AgentSafeError) as error:
            self.send_json(400, {"error": str(error)})

    def do_DELETE(self):
        if not self.path.startswith("/api/profiles/"):
            return self.send_json(404, {"error": "Not found"})
        profile_id = self.path.rsplit("/", 1)[-1]
        try:
            profiles, safe = self.migrate_legacy_profiles(self.profiles()), self.safe()
            try:
                safe.remove(self.config_key(profile_id))
            except KeyNotFoundError:
                pass
            self.save_profiles([profile for profile in profiles if profile.get("id") != profile_id])
            self.send_json(200, {"deleted": profile_id})
        except SecretStoreNotInitialized as error:
            self.send_json(503, {"code": "secrets_not_initialized", "error": str(error)})
        except (AgentSafeError, ValueError) as error:
            self.send_json(400, {"error": str(error)})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), PlaygroundHandler)
    print(f"OAuth Playground running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
