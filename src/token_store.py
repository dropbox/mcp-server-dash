"""Token persistence and validation for Dropbox OAuth access tokens."""

from __future__ import annotations

import json
import logging
import pathlib
from contextlib import suppress

import dropbox
import httpx
import keyring

logger = logging.getLogger(__name__)

# Constants for token storage
MCP_SERVER_DIR_NAME = ".mcp-server-dash"
TOKEN_FILENAME = "dropbox_token.json"

# Keyring service name for storing Dropbox tokens
KEYRING_SERVICE = "mcp-server-dash"
KEYRING_ACCESS_USERNAME = "dropbox_access_token"
KEYRING_REFRESH_USERNAME = "dropbox_refresh_token"

# Backward-compatible alias (older code/tests used KEYRING_USERNAME)
KEYRING_USERNAME = KEYRING_ACCESS_USERNAME


def get_default_token_dir() -> pathlib.Path:
    """Get a writable directory for token storage.

    Uses user's home directory/.mcp-server-dash/ which is guaranteed to be writable.
    Falls back to CWD if home directory is not accessible.
    """
    try:
        # Use user's home directory for reliable, writable storage
        home = pathlib.Path.home()
        token_dir = home / MCP_SERVER_DIR_NAME
        token_dir.mkdir(parents=True, exist_ok=True)
        return token_dir
    except Exception as e:
        logger.warning(f"Could not use home directory for token storage: {e}, falling back to CWD")
        return pathlib.Path.cwd()


class DropboxTokenStore:
    """Handles persistence and validation of a Dropbox OAuth access token.

    Uses the system keyring for secure token storage (access and refresh tokens
    stored under separate keys). Falls back to file-based storage
    (`dropbox_token.json`) when keyring is unavailable (e.g. headless Linux).
    """

    def __init__(self, base_dir: pathlib.Path | None = None) -> None:
        base = base_dir or get_default_token_dir()
        self._token_file = base / TOKEN_FILENAME
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.dbx: dropbox.Dropbox | None = None

    @property
    def token_file(self) -> pathlib.Path:
        return self._token_file

    @property
    def is_authenticated(self) -> bool:
        return bool(self.access_token and self.dbx)

    def clear(self) -> None:
        """Clear any saved token from keyring and delete legacy token files."""
        self.access_token = None
        self.refresh_token = None
        self.dbx = None
        # Remove from keyring
        with suppress(Exception):
            keyring.delete_password(KEYRING_SERVICE, KEYRING_ACCESS_USERNAME)
        with suppress(Exception):
            keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
        # Also clean up legacy key (old keyring username, for backward compat)
        with suppress(Exception):
            keyring.delete_password(KEYRING_SERVICE, "dropbox_access_token")

        # Remove file-based tokens
        with suppress(Exception):
            self._token_file.unlink(missing_ok=True)

    def _read_token_file(self, path: pathlib.Path) -> dict[str, str | None]:
        if not path.exists():
            return {}

        try:
            with path.open("r") as f:
                data = json.load(f)
            result = {}
            result["access_token"] = data.get("access_token")
            result["refresh_token"] = data.get("refresh_token")
            return result
        except Exception:
            return {}

    def _read_keyring(self) -> dict[str, str | None]:
        """Read both tokens from keyring."""
        try:
            access = keyring.get_password(KEYRING_SERVICE, KEYRING_ACCESS_USERNAME)
        except Exception:
            access = None
        try:
            refresh = keyring.get_password(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
        except Exception:
            refresh = None
        return {"access_token": access, "refresh_token": refresh}

    def load(self) -> bool:
        """Load token from keyring (or from file storage) and validate it.

        Returns True if a valid token is loaded, else False.
        If the access token is expired but a refresh token exists, attempts refresh.
        Transient network errors do NOT clear stored credentials.
        """
        try:
            # Load from keyring first, then file fallback
            keyring_data = self._read_keyring()
            file_data = self._read_token_file(self._token_file)

            access_token = keyring_data.get("access_token") or file_data.get("access_token")
            refresh_token = keyring_data.get("refresh_token") or file_data.get("refresh_token")

            if not access_token and not refresh_token:
                return False

            # Try access token first
            if access_token:
                try:
                    dbx = dropbox.Dropbox(access_token)
                    dbx.users_get_current_account()
                    self.access_token = access_token
                    self.refresh_token = refresh_token
                    self.dbx = dbx
                    return True
                except dropbox.exceptions.AuthError:
                    logger.info("Access token expired, trying refresh token")
                except Exception as e:
                    # Network/transient errors: do NOT clear — just return False
                    logger.warning("Access token validation failed (transient?): %s", e)
                    return False

            # Try refresh token
            if refresh_token:
                new_access = self._do_refresh(refresh_token)
                if new_access:
                    self.access_token = new_access
                    self.refresh_token = refresh_token
                    self.dbx = dropbox.Dropbox(new_access)
                    # Persist refreshed token to all backends
                    self._persist(new_access, refresh_token)
                    logger.info("Successfully refreshed access token")
                    return True
                else:
                    # Refresh definitively failed — credentials are invalid
                    logger.warning("Token refresh failed — clearing stored credentials")
                    self.clear()
                    return False

            self.clear()
            return False
        except Exception:
            self.clear()
            return False

    def _do_refresh(self, refresh_token: str) -> str | None:
        """Exchange a refresh token for a new access token via the Dropbox API.

        Returns the new access token, or None if refresh fails.
        Uses a direct HTTP call (no private SDK attributes).
        """
        import os

        app_key = os.environ.get("APP_KEY")
        if not app_key:
            logger.error("APP_KEY not set, cannot refresh token")
            return None
        try:
            with httpx.Client(timeout=30) as client:
                resp = client.post(
                    "https://api.dropboxapi.com/oauth2/token",
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                        "client_id": app_key,
                    },
                )
            if resp.status_code != 200:
                error_data = resp.json() if resp.text else {}
                logger.warning("Token refresh failed: %s", error_data.get("error_description", resp.text))
                return None
            token_data = resp.json()
            return token_data.get("access_token")
        except Exception as e:
            logger.warning("Token refresh request failed: %s", e)
            return None

    def try_refresh(self) -> bool:
        """Attempt a refresh using the stored refresh token.

        Called at runtime when an API call returns 401. Returns True on success.
        Does NOT clear credentials on failure — the caller decides.
        """
        if not self.refresh_token:
            return False
        new_access = self._do_refresh(self.refresh_token)
        if new_access:
            self.access_token = new_access
            self.dbx = dropbox.Dropbox(new_access)
            self._persist(new_access, self.refresh_token)
            logger.info("Runtime token refresh succeeded")
            return True
        return False

    def _save_to_file(self, access_token: str, refresh_token: str | None = None) -> None:
        """Save token data to file storage."""
        self._token_file.parent.mkdir(parents=True, exist_ok=True)
        data: dict[str, str] = {"access_token": access_token}
        if refresh_token:
            data["refresh_token"] = refresh_token
        with self._token_file.open("w") as f:
            json.dump(data, f)
        if hasattr(self._token_file, "chmod"):
            with suppress(Exception):
                self._token_file.chmod(0o600)
        logger.info(f"Token saved to file: {self._token_file}")

    def _persist(self, access_token: str, refresh_token: str | None) -> None:
        """Persist both tokens to keyring (preferred) and file (fallback).

        Tries keyring first for both tokens. If keyring is available, no
        plaintext file is written. If keyring fails, falls back to file.
        Raises RuntimeError if both backends fail.
        """
        keyring_ok = True
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_ACCESS_USERNAME, access_token)
        except Exception:
            keyring_ok = False

        if refresh_token and keyring_ok:
            with suppress(Exception):
                keyring.set_password(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME, refresh_token)

        if keyring_ok:
            logger.debug("Tokens saved to keyring successfully")
            return

        # Keyring failed — fall back to file
        logger.warning("Keyring unavailable, falling back to file storage")
        self._save_to_file(access_token, refresh_token)

    def save(self, token: str, refresh_token: str | None = None) -> None:
        """Persist token to keyring (or file as fallback) and set in-memory state.

        Raises RuntimeError if both keyring and file storage fail.
        """
        self._persist(token, refresh_token)

        self.access_token = token
        self.refresh_token = refresh_token
        self.dbx = dropbox.Dropbox(token)


def clear_token_interactive() -> None:
    """Interactive token clearing utility.

    Checks for tokens in keyring and file storage, displays their locations,
    prompts for confirmation, and clears them if confirmed.
    """
    store = DropboxTokenStore()

    # Check if tokens exist
    keyring_data = store._read_keyring()
    keyring_has_token = bool(keyring_data.get("access_token"))

    file_data = store._read_token_file(store.token_file)
    file_has_token = bool(file_data.get("access_token"))

    if not keyring_has_token and not file_has_token:
        print("No token found in either keyring or file storage.")
        return

    if keyring_has_token:
        print(f"Token found in keyring (service: {KEYRING_SERVICE})")
    if file_has_token:
        print(f"Token found in file (path: {store.token_file})")

    response = input("Do you want to remove the token? (y/N): ").strip().lower()

    if response == "y":
        store.clear()
        print("Token removed successfully.")
    else:
        print("Token not removed.")
