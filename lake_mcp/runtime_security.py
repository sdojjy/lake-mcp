"""Explicit local configuration and optional HTTP bearer authentication."""

import os
from pathlib import Path

from dotenv import load_dotenv


def load_config_file():
    # Never search parent directories: an unrelated ancestor .env is not policy.
    path = os.environ.get("LAKE_MCP_ENV_FILE")
    if path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            raise ValueError("LAKE_MCP_ENV_FILE must be an absolute path")
        if not candidate.is_file():
            raise ValueError("LAKE_MCP_ENV_FILE must name an existing file")
        load_dotenv(candidate, override=False)


def build_auth():
    from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

    token = os.environ.get("LAKE_MCP_AUTH_TOKEN")
    required = os.environ.get("LAKE_MCP_REQUIRE_AUTH", "false").lower()
    if required not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError("Invalid LAKE_MCP_REQUIRE_AUTH; use true or false")
    if token is not None and (not token.strip() or token != token.strip()):
        raise ValueError("LAKE_MCP_AUTH_TOKEN must be nonempty and have no surrounding whitespace")
    if required in {"true", "1", "yes", "on"} and not token:
        raise ValueError("LAKE_MCP_REQUIRE_AUTH requires LAKE_MCP_AUTH_TOKEN")
    if not token:
        return None
    return StaticTokenVerifier(tokens={token: {"client_id": "lake-mcp", "scopes": ["lake"]}}, required_scopes=["lake"])
