"""
Blackboard MCP Server - Entry Point

FastMCP Cloud runs this file. It imports and registers all tools from submodules.
"""
from fastmcp import FastMCP
from starlette.responses import RedirectResponse, HTMLResponse

from auth import (
    SERVER_URL,
    create_pending_auth,
    get_pending_auth,
    get_blackboard_auth_url,
    exchange_code_for_token,
    generate_user_token,
    store_user_credentials,
)
from templates import success_page, error_page
from tools.common import register_common_tools
from tools.student import register_student_tools
from tools.instructor import register_instructor_tools


# ============================================================================
# MCP SERVER
# ============================================================================

mcp = FastMCP("Blackboard")


# ============================================================================
# AUTH ROUTES
# ============================================================================

@mcp.custom_route("/auth/start", methods=["GET"])
async def auth_start(request):
    """Start the authentication flow"""
    state = create_pending_auth()
    return RedirectResponse(get_blackboard_auth_url(state))


@mcp.custom_route("/auth/callback", methods=["GET"])
async def auth_callback(request):
    """OAuth callback from Blackboard"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        return HTMLResponse(error_page(f"Authentication failed: {error}"), status_code=400)

    if not code or not state:
        return HTMLResponse(error_page("Missing required parameters"), status_code=400)

    if not get_pending_auth(state):
        return HTMLResponse(error_page("Invalid or expired session."), status_code=400)

    try:
        token_data = await exchange_code_for_token(code)
        
        user_token = generate_user_token()
        bb_user_id = token_data.get("user_id", "unknown")

        store_user_credentials(
            user_token=user_token,
            bb_access_token=token_data["access_token"],
            bb_refresh_token=token_data.get("refresh_token"),
            user_id=bb_user_id,
            expires_in=token_data.get("expires_in", 3600)
        )

        return HTMLResponse(success_page(user_token, bb_user_id))

    except Exception as e:
        return HTMLResponse(error_page(f"Error: {str(e)}"), status_code=500)


# ============================================================================
# REGISTER ALL TOOLS
# ============================================================================

register_common_tools(mcp)
register_student_tools(mcp)
register_instructor_tools(mcp)
