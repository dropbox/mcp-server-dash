"""MCP server exposing Dropbox Dash tools.

Tools include OAuth flow helpers, company-wide search, and file detail retrieval.
Authentication is persisted locally (token file), so you typically authenticate once
and reuse it until it expires or is revoked. Logging level is controlled by the
`LOG_LEVEL` env var (default: WARNING).
"""

import argparse
import asyncio
import functools
import logging
import os
import sys
from datetime import datetime
from typing import Any, Literal

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from auth_pkce import PKCEAuthFlow
from dash_api import (
    DashAPI,
    DashSearchRequest,
    DashSearchResponse,
    GetLinkMetadataRequest,
    GetLinkMetadataResponse,
)
from renderer import FieldSpec, render_section
from token_store import DropboxTokenStore

try:
    import dropbox as dropbox_mod
except ImportError:  # pragma: no cover - allow running tests without SDK
    dropbox_mod = None

# Single assignment for type-checkers
dropbox: Any = dropbox_mod

# Configure logging to stderr only with env-controlled level
_level_name = os.getenv("LOG_LEVEL", "WARNING").upper()
_level = getattr(logging, _level_name, logging.WARNING)
logging.basicConfig(
    level=_level, stream=sys.stderr, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load APP_KEY from environment and optional .env file
load_dotenv()
APP_KEY = os.getenv("APP_KEY")


token_store = DropboxTokenStore()
token_store.load()

# PKCE authentication flow handler
pkce_flow = PKCEAuthFlow()


def require_auth(func):
    """Decorator that ensures a valid Dropbox access token is available."""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        if not token_store.is_authenticated:
            return (
                "Not authenticated. Call dash_get_auth_url, then dash_authenticate with the code."
            )
        return await func(*args, **kwargs)

    return wrapper


def require_app_key(func):
    """Decorator that ensures APP_KEY is set."""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        if not APP_KEY or APP_KEY.startswith("your_"):
            return "Dropbox app key missing. Set APP_KEY in environment or .env file."
        return await func(*args, **kwargs)

    return wrapper


# Parse command-line arguments early to configure FastMCP properly
def _parse_args():
    """Parse command-line arguments to determine server configuration."""
    parser = argparse.ArgumentParser(
        description="Dropbox Dash MCP Server - Expose Dash search and file metadata via MCP"
    )
    parser.add_argument(
        "--mode",
        choices=["stdio", "server"],
        default="stdio",
        help="Transport mode: 'stdio' for Claude Desktop/Cursor (default), 'server' for SSE",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to in server mode (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to in server mode (default: 8000)",
    )
    parser.add_argument(
        "--clear-token",
        action="store_true",
        help="Clear stored Dropbox token from keyring and file storage, then exit",
    )
    parser.add_argument(
        "--ssl-keyfile",
        type=str,
        help="Path to SSL private key file for HTTPS (server mode only)",
    )
    parser.add_argument(
        "--ssl-certfile",
        type=str,
        help="Path to SSL certificate file for HTTPS (server mode only)",
    )
    return parser.parse_args()


# Parse args to get configuration for FastMCP initialization
_args = (
    _parse_args()
    if __name__ == "__main__"
    else argparse.Namespace(
        mode="stdio", host="127.0.0.1", port=8000, ssl_keyfile=None, ssl_certfile=None
    )
)

# Initialize fastmcp app with appropriate host/port for server mode.
# DNS rebinding protection: only accept requests whose Host header is loopback
# on the configured port. A rebound DNS name (e.g. *.attacker.tld) resolving to
# 127.0.0.1 will be rejected because the Host header carries the attacker
# hostname, not localhost. Origin is left unrestricted so legitimate same-origin
# MCP clients still work; the Host check alone breaks the rebinding path.
_allowed_hosts = [
    f"127.0.0.1:{_args.port}",
    f"localhost:{_args.port}",
    f"[::1]:{_args.port}",
]
mcp = FastMCP(
    "dash-mcp",
    host=_args.host,
    port=_args.port,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_allowed_hosts,
    ),
)


@mcp.tool()
@require_app_key
async def dash_get_auth_url() -> str:
    """Start Dropbox OAuth with PKCE; returns the authorization URL.

    When to use:
    - Use this when the user is not yet authenticated or if a previous token has expired.
      Visit the returned URL, approve access, then copy the one-time code shown by Dropbox.
    - Next, call `dash_authenticate(auth_code)` with that code to complete auth.
    - Authentication is cached in a local token file; you typically do this once and reuse it
      across sessions until it expires or is revoked.

    Requirements:
    - Environment must provide `APP_KEY` (via env or `.env`).

    Security:
    - This implementation uses PKCE (RFC 7636) to protect against authorization code interception.
      Even if an attacker intercepts the auth code, they cannot exchange it without the
      code_verifier that exists only in this server's memory.

    Returns (text):
    - A short instruction message followed by the authorization URL on its own line.
      Example:
        "Visit this URL to authorize Dropbox Dash...\n\nhttps://www.dropbox.com/…"

    Notes for LLMs:
    - If app credentials are missing, this tool returns a human-readable error string.
    - Use `dash_authenticate` immediately after the user completes the browser step.
    """
    try:
        # Type assertion: @require_app_key decorator guarantees APP_KEY is set
        assert APP_KEY is not None
        authorize_url = pkce_flow.generate_auth_url(APP_KEY)
        return (
            "Visit this URL to authorize Dropbox Dash. After authorizing, copy the code and "
            "call dash_authenticate(auth_code).\n\n"
            f"{authorize_url}"
        )
    except RuntimeError as e:
        return str(e)
    except Exception as e:
        logger.error(f"Error generating auth URL: {e}")
        return f"Error generating auth URL: {e}"


@mcp.tool()
@require_app_key
async def dash_authenticate(auth_code: str) -> str:
    """Complete Dropbox OAuth using the one-time authorization code with PKCE.

    Parameters:
    - auth_code: string (required) — the code the user copied from the Dropbox approval page.

    Security:
    - This implementation uses PKCE (RFC 7636) to protect against authorization code interception.
      The code_verifier generated in dash_get_auth_url is included in the token exchange to prove
      that the same client that initiated the flow is completing it.

    Returns (text):
    - On success: account display name and email, plus a confirmation that tools are available.
    - On failure: a human-readable error string (e.g., invalid/expired code or missing app creds).

    Notes for LLMs:
    - If not authenticated, guide the user to call `dash_get_auth_url`, approve in the browser,
      then call this tool with the displayed code.
    - On auth failures, instruct the user to restart the flow with a new auth URL.
    - A successful authentication persists a token using the local token store, so it usually
      only needs to be performed once until the token expires or is revoked.
    """
    global token_store
    try:
        # Type assertion: @require_app_key decorator guarantees APP_KEY is set
        assert APP_KEY is not None

        # Exchange authorization code for access token using PKCE (no secret needed)
        token_data = await pkce_flow.exchange_code_for_token(auth_code, APP_KEY)
        access_token = token_data.get("access_token")

        if not access_token or not isinstance(access_token, str):
            return "Authentication failed: no valid access token received from Dropbox."

        # Import dropbox here to get proper typing
        from auth_pkce import dropbox

        if dropbox is None:
            return "Dropbox SDK is not installed. Please install 'dropbox' to authenticate."

        # Validate by fetching account
        dbx = dropbox.Dropbox(access_token)
        account = dbx.users_get_current_account()

        try:
            token_store.save(access_token, token_data.get("refresh_token"))
        except Exception as e:
            logger.error(f"Failed to save token: {e}")
            return (
                "Authentication succeeded but failed to save token. Please try "
                "authenticating again."
            )

        logger.info("Successfully authenticated with PKCE")
        return (
            "Successfully authenticated with Dropbox!\n\n"
            f"Account: {account.name.display_name}\n"
            f"Email: {account.email}\n\n"
            "You can now use all Dropbox tools."
        )
    except RuntimeError as e:
        return str(e)
    except ValueError as e:
        return (
            f"Authentication failed: {e}\n\n"
            "Please restart the flow: call dash_get_auth_url, authorize, "
            "then retry with the new code."
        )
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        return (
            f"Authentication failed: {e}\n\n"
            "Please make sure you copied the authorization code correctly and try again."
        )


@mcp.tool()
@require_auth
async def dash_company_search(
    query: str,
    file_type: (
        Literal["document", "image", "video", "audio", "pdf", "presentation", "spreadsheet"] | None
    ) = None,
    connector: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    max_results: int = 20,
) -> str:
    """Search company content indexed by Dropbox Dash.

    Parameters:
    - query: string (required) — the search query text.
    - file_type: one of ["document","image","video","audio","pdf","presentation","spreadsheet"]
      or null for no filter. Default: null. The value "document" is also treated as no filter
      for backward compatibility.
    - connector: string (optional) — filter by connector source. Common connectors include
      "confluence", "dropbox", "github", "gmail", "gong", "google_calendar", "google_drive",
      "jira", "microsoft_365", "microsoft_teams", "slack", "workday", "zoom", among others.
      Default: null for no connector filter.
    - start_time: string (optional) — filter results modified after this datetime (ISO 8601 format,
      e.g., "2025-10-30T16:24:12.071Z"). Default: null for no start time filter.
    - end_time: string (optional) — filter results modified before this datetime (ISO 8601 format,
      e.g., "2025-10-31T16:24:12.071Z"). Default: null for no end time filter.
    - max_results: integer in [1..100]. Default: 20.

    Returns (text):
    - A formatted list of results. Each result contains predictable, labeled fields such as:
      "UUID:", "Type:", "URL:", "Preview:", "Description:", "File Type:", "MIME Type:",
      "Source:", "Creator:", "Last Modified By:", "Updated:", "Source Updated:",
      "Relevance:", "Source ID:". Results are separated by a divider line.

    Errors:
    - If unauthenticated, returns a human-readable instruction to re-authenticate.
    - If parameters are invalid (e.g., out-of-range `max_results` or unsupported `file_type`),
      returns a human-readable validation message.

    Notes for LLMs:
    - If the user is already authenticated (token cached), this tool can be called directly;
      otherwise guide them through `dash_get_auth_url` → `dash_authenticate`.
    - Use the returned "UUID" to fetch details with `dash_get_file_details(uuid)`.
    - Result formatting is stable: each line begins with an optional emoji, then a label and a
      colon (e.g., "🔑 UUID: …"). The divider consists of 50 em dashes.
    """
    try:
        # Validate inputs
        allowed_types = {
            "document",
            "image",
            "video",
            "audio",
            "pdf",
            "presentation",
            "spreadsheet",
        }
        if file_type is not None and file_type not in allowed_types:
            return (
                "Invalid file_type. Allowed: document, image, video, audio, pdf, presentation, "
                "spreadsheet; or null for no filter."
            )
        if not (1 <= int(max_results) <= 100):
            return "Invalid max_results. Must be between 1 and 100."

        api = DashAPI(token_store.access_token or "")
        req = DashSearchRequest(
            query_text=query,
            file_type=(file_type if file_type not in (None, "document") else None),
            connector_id=connector,
            start_datetime=start_time,
            end_datetime=end_time,
            max_results=max_results,
        )
        try:
            resp = await api.search(req)
        except PermissionError:
            # Token may be expired — try refresh before giving up
            if token_store.try_refresh():
                api = DashAPI(token_store.access_token or "")
                resp = await api.search(req)
            else:
                token_store.clear()
                return (
                    "Authorization failed (token invalid or expired). Please re-authenticate: "
                    "call dash_get_auth_url and then dash_authenticate with the new code."
                )
        if not resp.results:
            return f"Found 0 results for '{query}':\n\n"  # stable result count line
        return _format_search_response(resp, query)
    except Exception as e:
        logger.error(f"Error in Dash Search: {e}")
        return f"Error performing search: {e}"


@mcp.tool()
@require_auth
async def dash_get_file_details(uuid: str) -> str:
    """Fetch detailed metadata (and optional content snippet) for a result UUID.

    Parameters:
    - uuid: string (required) — the UUID obtained from `dash_company_search` results.

    Returns (text):
    - A human-readable summary including fields like: Title, Link, Updated, Source Updated,
      MIME Type, Source, Creator, Last Modified By. If media metadata is available, a section is
      included for video or image attributes. If body content is present, a "File Content" section
      includes the MIME type and a content preview.

    Content truncation:
    - Large bodies are truncated to ~20,000 characters and annotated with a note indicating the
      total length.

    Errors:
    - If unauthenticated, returns a human-readable instruction to re-authenticate.
    - If the UUID is not found, returns a human-readable message noting the missing file.

    Notes for LLMs:
    - The input UUID should come from `dash_company_search` results.
    - Lines follow a stable pattern: optional emoji, label, colon, then value (e.g., "🔗 Link: …").
    - Media sections are titled "🎞️ Video Metadata:" or "📷 Image Metadata:" when present.
    """
    try:
        api = DashAPI(token_store.access_token or "")
        req = GetLinkMetadataRequest(uuid=uuid)
        try:
            resp = await api.get_link_metadata(req)
        except PermissionError:
            if token_store.try_refresh():
                api = DashAPI(token_store.access_token or "")
                resp = await api.get_link_metadata(req)
            else:
                token_store.clear()
                return (
                    "Authorization failed (token invalid or expired). Please re-authenticate: "
                    "call dash_get_auth_url and then dash_authenticate with the new code."
                )
        if not resp.results:
            return f"No file found with UUID: {uuid}"
        return _format_file_details_response(resp, uuid)
    except Exception as e:
        logger.error(f"Error getting file details: {e}")
        return f"Error fetching file details: {e}"


# ---------------------
# Formatting helpers
# ---------------------


def _format_ts(ms: int | None) -> str:
    if ms and ms > 0:
        return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
    return "Unknown"


def _format_search_response(resp: DashSearchResponse, query: str) -> str:
    # helpers for transforms
    def record_type_label(v: object, _data: dict) -> str | None:
        # Accept string or {".tag": value}
        val: object | None = v
        if isinstance(val, dict):
            val = val.get(".tag")
        if not isinstance(val, str) or not val or val == "unknown_record_type":
            return None
        return val

    def preview_not_desc(val: str | None, data: dict) -> str | None:
        prev = data.get("preview")
        return val if val and val != prev else None

    def people_name(obj: dict | None, _data: dict) -> str | None:
        if not isinstance(obj, dict):
            return None
        return obj.get("display_name") or obj.get("email")

    text = f"Found {len(resp.results)} results for '{query}':\n\n"
    for i, item in enumerate(resp.results, 1):
        r = item.query_result
        if not r:
            continue
        data = r.model_dump() if hasattr(r, "model_dump") else dict(r)
        text += f"📄 Result {i}\n"
        specs = [
            FieldSpec("Title", "title", "📝"),
            FieldSpec("UUID", "uuid", "🔑"),
            FieldSpec("Type", "record_type", "📋", record_type_label),
            FieldSpec("URL", "url", "🔗"),
            FieldSpec("Display Name", "display_name", "👤"),
            FieldSpec("Email", "email", "📧"),
            FieldSpec("Preview", "preview", "📝"),
            FieldSpec("Description", "description", "📄", preview_not_desc),
            FieldSpec("File Type", "file_type_info.display_name", "📁"),
            FieldSpec("MIME Type", "mime_type", "🔧"),
            FieldSpec("Source", "connector_info.connector_id", "🔌"),
            FieldSpec("Creator", "creator", "✏️", people_name),
            FieldSpec("Last Modified By", "last_modifier", "🔄", people_name),
            FieldSpec("Updated", "updated_at_ms", "📅", lambda v, d: _format_ts(v)),
            FieldSpec(
                "Source Updated",
                "provider_updated_at_ms",
                "📅",
                lambda v, d: _format_ts(v) if v and v != d.get("updated_at_ms") else None,
            ),
            FieldSpec(
                "Relevance",
                "relevance_score",
                "⭐",
                lambda v, d: f"{v:.2f}" if isinstance(v, int | float) and v > 0 else None,
            ),
            FieldSpec("Source ID", "upstream_id", "🔗"),
        ]
        block = render_section(None, specs, data).rstrip()
        if block:
            text += block + "\n"
        text += "—" * 50 + "\n\n"
    return text


def _format_file_details_response(resp: GetLinkMetadataResponse, uuid: str) -> str:
    def people_name(obj: dict | None, _data: dict) -> str | None:
        if not isinstance(obj, dict):
            return None
        return obj.get("display_name") or obj.get("email")

    m = resp.results[0]
    data = m.model_dump() if hasattr(m, "model_dump") else dict(m)
    text = f"📄 **File Details for UUID: {uuid}**\n\n"
    title = data.get("title") or "Untitled"
    if data.get("error_code"):
        text += f"❌ Error: {data.get('error_code')}\n"
        if data.get("error_message"):
            text += f"💬 Error Message: {data.get('error_message')}\n"
        return text
    text += f"📝 Title: {title}\n"

    core_specs = [
        FieldSpec("Link", "link", "🔗"),
        FieldSpec("Updated", "updated_at_ms", "📅", lambda v, d: _format_ts(v)),
        FieldSpec(
            "Source Updated",
            "provider_last_updated_at_ms",
            "📅",
            lambda v, d: _format_ts(v) if v and v != data.get("updated_at_ms") else None,
        ),
        FieldSpec("MIME Type", "mime_type", "🔧"),
        FieldSpec("Source", "connector_info.connector_id", "🔌"),
        FieldSpec("Creator", "creator", "✏️", people_name),
        FieldSpec("Last Modified By", "last_modifier", "🔄", people_name),
    ]
    core_block = render_section(None, core_specs, data).rstrip()
    if core_block:
        text += core_block + "\n"

    media = data.get("media_metadata") or {}
    video = media.get("video_metadata") or {}
    if video:
        video_specs = [
            FieldSpec(
                "Duration",
                "duration_ms",
                "⏱️",
                lambda v, d: f"{round(v/1000,2)} seconds" if v is not None else None,
            ),
            FieldSpec(
                "Dimensions",
                "width",
                "📐",
                lambda v, d: (
                    f"{v} x {video.get('height')} pixels" if v and video.get("height") else None
                ),
            ),
        ]
        section = render_section("🎞️ Video Metadata:", video_specs, video).rstrip()
        if section:
            text += section + "\n"

    image = media.get("image_metadata") or {}
    if image:
        image_specs = [
            FieldSpec(
                "Dimensions",
                "image_width",
                "📐",
                lambda v, d: (
                    f"{v} x {image.get('image_height')} pixels"
                    if v and image.get("image_height")
                    else None
                ),
            ),
            FieldSpec(
                "Camera",
                "camera_make",
                "📸",
                lambda v, d: (f"{v or ''} {image.get('camera_model') or ''}").strip() or None,
            ),
            FieldSpec("Creator", "creator", "👤"),
            FieldSpec("Date Taken", "date_time_original", "📅"),
        ]
        section = render_section("📷 Image Metadata:", image_specs, image).rstrip()
        if section:
            text += section + "\n"

    thumb = (data.get("thumbnail") or {}).get("blob_content", {})
    raw_thumb = (thumb.get("raw_content") or {}) if thumb else {}
    thumb_block = render_section(
        None, [FieldSpec("Thumbnail Available", "mime_type", "🖼️")], raw_thumb
    ).rstrip()
    if thumb_block:
        text += thumb_block + "\n"

    body_blob = (data.get("body") or {}).get("blob_content", {})

    def limit_raw(v, _d):
        if not v:
            return None
        return (
            f"{v[:20000]}...\n[Content truncated - total length: {len(v)} characters]"
            if len(v) > 20000
            else v
        )

    body_specs = [
        FieldSpec("MIME Type", "mime_type", "🔧"),
        FieldSpec("Content", "raw", "📝", limit_raw),
    ]
    body_block = render_section("📄 File Content:", body_specs, body_blob).rstrip()
    if body_block:
        text += body_block + "\n"

    return text.rstrip()


def main() -> None:
    """Main entry point with support for both stdio and server modes."""
    # Handle --clear-token flag
    if _args.clear_token:
        from token_store import clear_token_interactive

        clear_token_interactive()
        sys.exit(0)

    if _args.mode == "server":
        # Server mode with SSE transport
        # Validate SSL configuration
        ssl_enabled = False
        if _args.ssl_keyfile or _args.ssl_certfile:
            if not _args.ssl_keyfile or not _args.ssl_certfile:
                print(
                    "Error: Both --ssl-keyfile and --ssl-certfile must be provided for HTTPS",
                    file=sys.stderr,
                )
                sys.exit(1)
            if not os.path.exists(_args.ssl_keyfile):
                print(f"Error: SSL key file not found: {_args.ssl_keyfile}", file=sys.stderr)
                sys.exit(1)
            if not os.path.exists(_args.ssl_certfile):
                print(
                    f"Error: SSL certificate file not found: {_args.ssl_certfile}", file=sys.stderr
                )
                sys.exit(1)
            ssl_enabled = True

        protocol = "https" if ssl_enabled else "http"
        logger.info(
            f"Starting Dash MCP Server in server mode on {protocol}://{_args.host}:{_args.port}"
        )
        print(
            f"Dash MCP Server is running in server mode on {protocol}://{_args.host}:{_args.port}/mcp"
        )

        # If SSL is enabled, we need to use uvicorn directly since FastMCP doesn't expose SSL config
        if ssl_enabled:
            import uvicorn

            # Get the Starlette app from FastMCP
            starlette_app = mcp.streamable_http_app()

            # Create uvicorn config with SSL
            config = uvicorn.Config(
                starlette_app,
                host=_args.host,
                port=_args.port,
                log_level=_level_name.lower(),
                ssl_keyfile=_args.ssl_keyfile,
                ssl_certfile=_args.ssl_certfile,
            )
            server = uvicorn.Server(config)
            asyncio.run(server.serve())
        else:
            mcp.run(transport="streamable-http")
    else:
        # STDIO mode (default)
        logger.info("Starting Dash MCP Server in stdio mode")
        print("Dash MCP Server is running in stdio mode...", file=sys.stderr)
        mcp.run()


if __name__ == "__main__":
    # Allow running under asyncio-based hosts or directly
    if asyncio.get_event_loop_policy().__class__.__name__ == "WindowsProactorEventLoopPolicy":
        # Fast path for Windows compatibility if ever needed
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined]
    main()
