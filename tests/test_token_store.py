import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import token_store as ts


class FakeDropbox:
    def __init__(self, token: str, *, valid: bool = True):
        self.token = token
        self._valid = valid

    def users_get_current_account(self):
        if not self._valid:
            raise ts.dropbox.exceptions.AuthError("request_id", "invalid_token")
        return SimpleNamespace(name=SimpleNamespace(display_name="Test"), email="e@example.com")


class FakeKeyring:
    """Mock keyring for testing."""

    def __init__(self):
        self._store = {}

    def get_password(self, service, username):
        return self._store.get((service, username))

    def set_password(self, service, username, password):
        self._store[(service, username)] = password

    def delete_password(self, service, username):
        self._store.pop((service, username), None)


def setup_store(tmp_path, monkeypatch, keyring_available=True):
    """Helper to setup store with fake keyring and dropbox."""
    fake_keyring = FakeKeyring()
    monkeypatch.setattr(ts, "keyring", fake_keyring)
    monkeypatch.setattr(ts.dropbox, "Dropbox", lambda token: FakeDropbox(token, valid=True))

    if not keyring_available:
        fake_keyring.set_password = Mock(side_effect=RuntimeError("Keyring unavailable"))

    return ts.DropboxTokenStore(base_dir=tmp_path), fake_keyring


def test_save_and_load_valid_token(tmp_path, monkeypatch):
    store, keyring = setup_store(tmp_path, monkeypatch)

    store.save("abc")
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) == "abc"
    assert not store.token_file.exists()

    store2 = ts.DropboxTokenStore(base_dir=tmp_path)
    assert store2.load()
    assert store2.is_authenticated
    assert store2.access_token == "abc"


def test_save_and_load_with_refresh_token(tmp_path, monkeypatch):
    """save() should persist refresh_token to keyring and load() should find it."""
    store, keyring = setup_store(tmp_path, monkeypatch)

    store.save("access123", "refresh456")
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) == "access123"
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_REFRESH_USERNAME) == "refresh456"
    assert not store.token_file.exists()  # No file when keyring works
    assert store.refresh_token == "refresh456"

    store2 = ts.DropboxTokenStore(base_dir=tmp_path)
    assert store2.load()
    assert store2.access_token == "access123"
    assert store2.refresh_token == "refresh456"


def test_load_invalid_token_with_refresh_succeeds(tmp_path, monkeypatch):
    """If access token is expired but refresh token exists, load() should refresh."""
    store, keyring = setup_store(tmp_path, monkeypatch)

    # Simulate: keyring has expired access token + valid refresh token
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "expired_access")
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_REFRESH_USERNAME, "valid_refresh")

    # First call with expired access fails, then _do_refresh returns new token
    call_count = [0]
    def fake_dropbox(token):
        call_count[0] += 1
        if call_count[0] == 1:
            return FakeDropbox(token, valid=False)
        return FakeDropbox(token, valid=True)
    monkeypatch.setattr(ts.dropbox, "Dropbox", fake_dropbox)

    # Mock _do_refresh to return a new access token
    monkeypatch.setattr(store, "_do_refresh", lambda rt: "new_access_token")

    assert store.load()
    assert store.access_token == "new_access_token"
    assert store.refresh_token == "valid_refresh"


def test_load_invalid_token_with_refresh_fails_clears(tmp_path, monkeypatch):
    """If both access and refresh fail, clear() should be called."""
    store, keyring = setup_store(tmp_path, monkeypatch)

    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "expired")
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_REFRESH_USERNAME, "bad_refresh")

    monkeypatch.setattr(ts.dropbox, "Dropbox", lambda token: FakeDropbox(token, valid=False))
    monkeypatch.setattr(store, "_do_refresh", lambda rt: None)

    assert not store.load()
    assert not store.is_authenticated
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) is None


def test_load_network_error_does_not_clear(tmp_path, monkeypatch):
    """Transient network errors should NOT clear stored credentials."""
    store, keyring = setup_store(tmp_path, monkeypatch)

    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "maybe_valid")
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_REFRESH_USERNAME, "refresh")

    # Simulate network error (not AuthError)
    class NetworkError(Exception):
        pass

    def network_fail(token):
        raise NetworkError("Connection refused")

    monkeypatch.setattr(ts.dropbox, "Dropbox", network_fail)

    assert not store.load()
    assert not store.is_authenticated
    # Tokens should still be in keyring — NOT cleared
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) == "maybe_valid"
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_REFRESH_USERNAME) == "refresh"


def test_load_invalid_token_clears_state(tmp_path, monkeypatch):
    store, keyring = setup_store(tmp_path, monkeypatch)
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "bad_token")
    monkeypatch.setattr(ts.dropbox, "Dropbox", lambda token: FakeDropbox(token, valid=False))

    assert not store.load()
    assert not store.is_authenticated
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) is None


def test_clear_removes_token_from_keyring(tmp_path, monkeypatch):
    store, keyring = setup_store(tmp_path, monkeypatch)

    store.save("abc")
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) == "abc"

    store.clear()
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) is None
    assert not store.is_authenticated


def test_load_from_file(tmp_path, monkeypatch):
    store, _ = setup_store(tmp_path, monkeypatch)
    (tmp_path / "dropbox_token.json").write_text(json.dumps({"access_token": "file_token"}))

    assert store.load()
    assert store.access_token == "file_token"


def test_load_no_token_exists(tmp_path, monkeypatch):
    store, _ = setup_store(tmp_path, monkeypatch)

    assert not store.load()
    assert not store.is_authenticated


def test_save_fallback_to_file(tmp_path, monkeypatch):
    store, _ = setup_store(tmp_path, monkeypatch, keyring_available=False)

    store.save("fallback_token")

    assert store.token_file.exists()
    assert json.loads(store.token_file.read_text())["access_token"] == "fallback_token"
    assert store.access_token == "fallback_token"


def test_save_fallback_to_file_with_refresh(tmp_path, monkeypatch):
    """When keyring fails, both tokens should go to file."""
    store, _ = setup_store(tmp_path, monkeypatch, keyring_available=False)

    store.save("access_tok", "refresh_tok")

    data = json.loads(store.token_file.read_text())
    assert data["access_token"] == "access_tok"
    assert data["refresh_token"] == "refresh_tok"


def test_save_both_keyring_and_file_fail(tmp_path, monkeypatch):
    store, _ = setup_store(tmp_path, monkeypatch, keyring_available=False)
    tmp_path.chmod(0o400)

    try:
        with pytest.raises((RuntimeError, OSError, PermissionError)):
            store.save("test_token")
    finally:
        tmp_path.chmod(0o700)


@pytest.mark.parametrize(
    "content,reason",
    [
        ("not valid json {", "corrupt JSON"),
        (json.dumps({"other_key": "value"}), "missing access_token key"),
        (json.dumps({"access_token": ""}), "empty access_token"),
    ],
)
def test_read_token_file_invalid(tmp_path, content, reason):
    store = ts.DropboxTokenStore(base_dir=tmp_path)
    store.token_file.write_text(content)

    result = store._read_token_file(store.token_file)
    assert isinstance(result, dict)
    assert not result.get("access_token")


def test_load_generic_exception(tmp_path, monkeypatch):
    """Generic (transient) errors should NOT clear stored credentials."""
    store, keyring = setup_store(tmp_path, monkeypatch)
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "test_token")
    monkeypatch.setattr(
        ts.dropbox, "Dropbox", lambda token: (_ for _ in ()).throw(Exception("Error"))
    )

    assert not store.load()
    assert not store.is_authenticated
    # Transient errors should preserve stored tokens
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) == "test_token"


def test_clear_removes_file_token(tmp_path, monkeypatch):
    store, _ = setup_store(tmp_path, monkeypatch)
    store.token_file.write_text(json.dumps({"access_token": "file_token"}))

    store.clear()

    assert not store.token_file.exists()
    assert not store.is_authenticated


def test_token_file_property(tmp_path):
    store = ts.DropboxTokenStore(base_dir=tmp_path)
    assert store.token_file == tmp_path / "dropbox_token.json"


def test_get_default_token_dir_fallback(monkeypatch):
    monkeypatch.setattr(ts.pathlib.Path, "home", lambda: (_ for _ in ()).throw(RuntimeError()))
    assert ts.get_default_token_dir() == ts.pathlib.Path.cwd()


def test_try_refresh_success(tmp_path, monkeypatch):
    """try_refresh() should update tokens and return True."""
    store, keyring = setup_store(tmp_path, monkeypatch)
    store.access_token = "old_token"
    store.refresh_token = "valid_refresh"
    store.dbx = FakeDropbox("old_token", valid=True)

    monkeypatch.setattr(store, "_do_refresh", lambda rt: "new_token")

    assert store.try_refresh() is True
    assert store.access_token == "new_token"
    # Keyring should be updated
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) == "new_token"


def test_try_refresh_no_refresh_token(tmp_path, monkeypatch):
    """try_refresh() should return False if no refresh token."""
    store, _ = setup_store(tmp_path, monkeypatch)
    store.access_token = "some_token"
    store.refresh_token = None

    assert store.try_refresh() is False


def test_try_refresh_failure(tmp_path, monkeypatch):
    """try_refresh() should return False (not clear) when refresh fails."""
    store, keyring = setup_store(tmp_path, monkeypatch)
    store.access_token = "expired"
    store.refresh_token = "also_bad"

    monkeypatch.setattr(store, "_do_refresh", lambda rt: None)

    assert store.try_refresh() is False
    # Credentials should NOT be cleared by try_refresh (caller decides)
    assert store.refresh_token == "also_bad"


def test_try_refresh_transient_error(tmp_path, monkeypatch):
    """try_refresh() should return False (not raise) on transient errors."""
    store, keyring = setup_store(tmp_path, monkeypatch)
    store.access_token = "expired"
    store.refresh_token = "valid_but_network_down"

    def raise_transient(rt):
        raise ts.TransientRefreshError("Connection refused")

    monkeypatch.setattr(store, "_do_refresh", raise_transient)

    assert store.try_refresh() is False
    # Credentials preserved — not cleared
    assert store.refresh_token == "valid_but_network_down"


def test_load_refresh_transient_does_not_clear(tmp_path, monkeypatch):
    """Transient network error during refresh must NOT clear stored credentials."""
    store, keyring = setup_store(tmp_path, monkeypatch)

    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "expired_access")
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_REFRESH_USERNAME, "valid_refresh")

    monkeypatch.setattr(ts.dropbox, "Dropbox", lambda token: FakeDropbox(token, valid=False))

    def raise_transient(rt):
        raise ts.TransientRefreshError("Server unreachable")

    monkeypatch.setattr(store, "_do_refresh", raise_transient)

    assert not store.load()
    assert not store.is_authenticated
    # Both tokens should still be in keyring — NOT cleared
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) == "expired_access"
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_REFRESH_USERNAME) == "valid_refresh"


def test_persist_refresh_keyring_failure_falls_back_to_file(tmp_path, monkeypatch):
    """If refresh_token keyring write fails but access succeeds, fall back to file."""
    store, keyring = setup_store(tmp_path, monkeypatch)

    # Access succeeds but refresh write will fail
    original_set = keyring.set_password
    call_count = [0]

    def flaky_set(service, username, password):
        call_count[0] += 1
        if username == ts.KEYRING_REFRESH_USERNAME:
            raise RuntimeError("Keyring hiccup on second write")
        original_set(service, username, password)

    monkeypatch.setattr(keyring, "set_password", flaky_set)

    store.save("access_tok", "refresh_tok")

    # File should exist with BOTH tokens (fallback for both)
    data = json.loads(store.token_file.read_text())
    assert data["access_token"] == "access_tok"
    assert data["refresh_token"] == "refresh_tok"
    # In-memory state should be correct
    assert store.access_token == "access_tok"
    assert store.refresh_token == "refresh_tok"


def _setup_interactive_test(tmp_path, monkeypatch, user_input="y"):
    """Helper to setup interactive clearing tests."""
    keyring = FakeKeyring()
    monkeypatch.setattr(ts, "keyring", keyring)
    monkeypatch.setattr(ts, "get_default_token_dir", lambda: tmp_path)
    monkeypatch.setattr("builtins.input", lambda _: user_input)
    return keyring, tmp_path / "dropbox_token.json"


def test_clear_token_interactive_no_token(tmp_path, monkeypatch, capsys):
    _setup_interactive_test(tmp_path, monkeypatch)
    ts.clear_token_interactive()
    assert "No token found" in capsys.readouterr().out


def test_clear_token_interactive_keyring_confirm(tmp_path, monkeypatch, capsys):
    keyring, _ = _setup_interactive_test(tmp_path, monkeypatch, "y")
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "test_token")

    ts.clear_token_interactive()

    out = capsys.readouterr().out
    assert "Token found in keyring" in out
    assert "Token removed successfully" in out
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) is None


def test_clear_token_interactive_keyring_decline(tmp_path, monkeypatch, capsys):
    keyring, _ = _setup_interactive_test(tmp_path, monkeypatch, "n")
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "test_token")

    ts.clear_token_interactive()

    out = capsys.readouterr().out
    assert "Token found in keyring" in out
    assert "Token not removed" in out
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) == "test_token"


def test_clear_token_interactive_file(tmp_path, monkeypatch, capsys):
    _, token_file = _setup_interactive_test(tmp_path, monkeypatch, "y")
    token_file.write_text(json.dumps({"access_token": "file_token"}))

    ts.clear_token_interactive()

    out = capsys.readouterr().out
    assert "Token found in file" in out
    assert str(token_file) in out
    assert "Token removed successfully" in out
    assert not token_file.exists()


def test_clear_token_interactive_both(tmp_path, monkeypatch, capsys):
    keyring, token_file = _setup_interactive_test(tmp_path, monkeypatch, "y")
    keyring.set_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME, "keyring_token")
    token_file.write_text(json.dumps({"access_token": "file_token"}))

    ts.clear_token_interactive()

    out = capsys.readouterr().out
    assert "Token found in keyring" in out
    assert "Token found in file" in out
    assert "Token removed successfully" in out
    assert keyring.get_password(ts.KEYRING_SERVICE, ts.KEYRING_ACCESS_USERNAME) is None
    assert not token_file.exists()
