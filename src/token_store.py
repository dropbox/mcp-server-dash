"""Token persistence and validation for Dropbox OAuth access tokens."""

from __future__ import annotations

import json
import logging
import pathlib
from contextlib import suppress

import dropbox
import keyring

logger = logging.getLogger(__name__)

# Constants for token storage
MCP_SERVER_DIR_NAME = ".mcp-server-dash"
TOKEN_FILENAME = "dropbox_token.json"

# Keyring service name for storing Dropbox tokens
KEYRING_SERVICE = "mcp-server-dash"
KEYRING_USERNAME = "dropbox_access_token"


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

    Uses the system keyring for secure token storage. Falls back to reading
    from legacy file-based storage (`dropbox_token.json`).
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
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)

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

    def load(self) -> bool:
        """Load token from keyring (or from file storage) and validate it.

        Returns True if a valid token is loaded, else False.
        If the access token is expired but a refresh token exists, attempts refresh.
        """
        try:
            access_token = None
            refresh_token = None
            # Primary: Load access token from keyring
            access_token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)

            # Fallback: file-based storage
            token_data = self._read_token_file(self._token_file)
            if not access_token:
                access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")

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
                    logger.warning("Access token expired, trying refresh token")
                except Exception:
                    logger.warning("Access token validation failed, trying refresh token")

            # Try refresh token
            if refresh_token:
                import os
                app_key = os.environ.get("APP_KEY")
                if not app_key:
                    logger.error("APP_KEY not set, cannot refresh token")
                    return False
                try:
                    dbx = dropbox.Dropbox(
                        oauth2_refresh_token=refresh_token,
                        app_key=app_key,
                    )
                    dbx.users_get_current_account()
                    # Get the new access token from the client
                    new_access_token = dbx._oauth2_access_token
                    self.access_token = new_access_token
                    self.refresh_token = refresh_token
                    self.dbx = dbx
                    # Persist the refreshed token
                    self._save_to_file(new_access_token, refresh_token)
                    logger.info("Successfully refreshed access token")
                    return True
                except Exception as e:
                    logger.warning("Token refresh failed: %s", e)
                    self.clear()
                    return False

            self.clear()
            return False
        except Exception:
            self.clear()
            return False

    def _save_to_file(self, access_token: str, refresh_token: str | None = None) -> None:
        """Save token data to file storage."""
        self._token_file.parent.mkdir(parents=True, exist_ok=True)
        data = {"access_token": access_token}
        if refresh_token:
            data["refresh_token"] = refresh_token
        with self._token_file.open("w") as f:
            json.dump(data, f)
        if hasattr(self._token_file, "chmod"):
            with suppress(Exception):
                self._token_file.chmod(0o600)
        logger.info(f"Token saved to file: {self._token_file}")

    def save(self, token: str, refresh_token: str | None = None) -> None:
        """Persist token to keyring and file, and set in-memory state."""
        # Always save to file (includes refresh_token — keyring only stores access_token)
        try:
            self._save_to_file(token, refresh_token)
        except Exception as file_error:
            logger.error(f"Failed to save token to file: {file_error}")

        # Also try keyring as a secondary store
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, token)
            logger.debug("Token saved to keyring successfully")
        except Exception as e:
            logger.warning(f"Failed to save token to keyring: {e}")

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
    keyring_token = None
    with suppress(Exception):
        keyring_token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)

    file_token = None
    if store.token_file.exists():
        file_token = store._read_token_file(store.token_file)

    if not keyring_token and not file_token:
        print("No token found in either keyring or file storage.")
        return

    if keyring_token:
        print(f"Token found in keyring (service: {KEYRING_SERVICE})")
    if file_token:
        print(f"Token found in file (path: {store.token_file})")

    response = input("Do you want to remove the token? (y/N): ").strip().lower()

    if response == "y":
        store.clear()
        print("Token removed successfully.")
    else:
        print("Token not removed.")
