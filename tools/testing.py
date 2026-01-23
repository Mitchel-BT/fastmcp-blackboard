"""
Testing/Debug tools for Blackboard MCP Server.

This version avoids importing `Depends` from fastmcp (some fastmcp versions
do not export Depends). Instead, it resolves the Blackboard token in a way
that works in both local and cloud modes.
"""

import sys
import httpx

import blackboard_client as bb
from blackboard_client import BlackboardAPIError

from fastmcp.server.dependencies import get_access_token

from auth import (
    IS_LOCAL_MODE,
    BLACKBOARD_URL,
    SERVER_URL,
    get_local_token,
    get_bb_token,
)


async def _resolve_bb_token() -> str:
    """
    Resolve the Blackboard token in both modes:

    - Local mode: token is stored by browser OAuth and returned by get_bb_token()
    - Cloud mode: token comes from FastMCP injection via get_access_token()
    """
    if IS_LOCAL_MODE:
        # In local mode, get_bb_token ignores its argument and uses the stored local token.
        return get_bb_token(None)

    # Cloud mode: pull the injected access token from FastMCP, then pass through get_bb_token()
    # (which in cloud mode simply returns the injected token).
    mcp_access_token = await get_access_token()
    return get_bb_token(mcp_access_token)


def register_testing_tools(mcp):
    """Register testing/debug tools with the MCP server."""

    @mcp.tool()
    async def which_server() -> dict:
        return {
            "server_file": __file__,
            "sys_path_head": sys.path[:3],
            "mode": "LOCAL" if IS_LOCAL_MODE else "CLOUD",
        }

    @mcp.tool()
    async def whoami() -> dict:
        """
        [Testing] Return the currently authenticated Blackboard user.
        """
        try:
            bb_token = await _resolve_bb_token()
            user = await bb.get_current_user(access_token=bb_token)
            return {
                "success": True,
                "userName": user.get("userName"),
                "id": user.get("id"),
            }
        except ValueError as e:
            return {"error": "not_authenticated", "message": str(e)}
        except BlackboardAPIError as e:
            return {
                "error": "api_error",
                "message": getattr(e, "message", str(e)),
                "status_code": getattr(e, "status_code", None),
                "details": getattr(e, "details", None),
            }
        except Exception as e:
            return {"error": "unexpected_error", "message": str(e), "exception_type": type(e).__name__}

    @mcp.tool()
    async def debug_auth_state() -> dict:
        """
        [Debug] Show current auth state and token previews.
        """
        result = {
            "mode": "LOCAL" if IS_LOCAL_MODE else "CLOUD",
            "blackboard_url": BLACKBOARD_URL,
            "server_url": SERVER_URL or "(not set)",
        }

        if IS_LOCAL_MODE:
            local_token = get_local_token()
            result["local_token_set"] = local_token is not None
            result["local_token_preview"] = (
                f"{local_token[:8]}...{local_token[-4:]}" if local_token else None
            )

        try:
            bb_token = await _resolve_bb_token()
            result["bb_token_resolved"] = True
            result["bb_token_preview"] = f"{bb_token[:8]}...{bb_token[-4:]}"
        except Exception as e:
            result["bb_token_resolved"] = False
            result["bb_token_error"] = str(e)

        # In cloud mode, also show that get_access_token works (without leaking full token)
        if not IS_LOCAL_MODE:
            try:
                mcp_token = await get_access_token()
                result["mcp_access_token_preview"] = (
                    f"{mcp_token[:8]}...{mcp_token[-4:]}" if mcp_token else None
                )
            except Exception as e:
                result["mcp_access_token_error"] = str(e)

        return result

    @mcp.tool()
    async def debug_test_api_call() -> dict:
        """
        [Debug] Raw GET /users/me to verify token works against Blackboard.
        """
        try:
            token = await _resolve_bb_token()
        except Exception as e:
            return {"error": f"Could not resolve token: {e}"}

        if not token:
            return {"error": "No token available", "token_is_none": True}

        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"{BLACKBOARD_URL}/learn/api/public/v1/users/me",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0,
                )
                return {
                    "status_code": r.status_code,
                    "success": r.status_code == 200,
                    "response": r.json() if r.status_code == 200 else r.text[:500],
                }
        except Exception as e:
            return {"error": str(e), "exception_type": type(e).__name__}
