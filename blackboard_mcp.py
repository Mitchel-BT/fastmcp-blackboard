"""
Blackboard MCP Server - Cloud Version with Correct OAuth Flow
Fixed to match Blackboard's 3-Legged OAuth specification
"""
import os
import base64
import secrets
import time
import logging
import httpx
from urllib.parse import urlencode
from fastmcp import FastMCP, Context
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_context
from starlette.responses import RedirectResponse, JSONResponse

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("blackboard-mcp")

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")  # e.g., https://your-school.blackboard.com
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

TOKEN_EXPIRY_SECONDS = 3600

# ============================================================================
# SESSION STORAGE - Per Connection
# ============================================================================
_sessions = {}  # connection_id -> {token_data, timestamp, user_id}
_pending_auths = {}  # state -> {connection_id, redirect_uri, etc}
_auth_codes = {}  # code -> {connection_id, token_data}
_completed_states = {}  # state -> cached redirect info

# ============================================================================
# ENHANCED SESSION MANAGEMENT
# ============================================================================

@mcp.tool()
async def logout() -> str:
    """
    Log out from Blackboard by clearing your authentication session.
    This will remove your current session and require re-authentication.
    """
    token, token_data, authenticated, connection_id = get_user_session()
    
    if not authenticated or not connection_id:
        return "ℹ️ You are not currently logged in."
    
    if connection_id in _sessions:
        user_id = token_data.get("user_id", "unknown") if token_data else "unknown"
        username = token_data.get("username", user_id) if token_data else user_id
        
        # Remove the session
        del _sessions[connection_id]
        
        logger.info(f"Tool: logout - Removed session for connection {connection_id[:20]}... (user {user_id})")
        logger.info(f"Tool: Active sessions remaining: {len(_sessions)}")
        
        return (
            f"✅ **Successfully Logged Out**\n\n"
            f"• User: `{username}`\n"
            f"• Connection: `{connection_id[:20]}...`\n\n"
            f"You can now authenticate as a different user or log back in."
        )
    
    return "ℹ️ No active session found to log out."


@mcp.tool()
async def force_logout(connection_id_prefix: str) -> str:
    """
    Force logout a specific session by connection ID prefix.
    Useful for demo cleanup or managing multiple test accounts.
    
    Args:
        connection_id_prefix: First 8+ characters of the connection ID to logout
    """
    if len(connection_id_prefix) < 8:
        return "❌ Please provide at least 8 characters of the connection ID for safety."
    
    cleanup_expired()
    
    # Find matching sessions
    matches = [
        conn_id for conn_id in _sessions.keys()
        if conn_id.startswith(connection_id_prefix)
    ]
    
    if not matches:
        return (
            f"❌ No sessions found matching prefix `{connection_id_prefix}`\n\n"
            f"Active sessions: {len(_sessions)}\n"
            f"Use `list_active_sessions` to see all sessions."
        )
    
    if len(matches) > 1:
        result = f"⚠️ Found {len(matches)} matching sessions:\n\n"
        for conn_id in matches:
            session = _sessions[conn_id]
            user_id = session.get("user_id", "unknown")
            result += f"• `{conn_id[:20]}...` - User: {user_id}\n"
        result += "\nPlease provide a longer prefix to uniquely identify the session."
        return result
    
    # Single match - logout
    conn_id = matches[0]
    session = _sessions[conn_id]
    user_id = session.get("user_id", "unknown")
    
    del _sessions[conn_id]
    
    logger.info(f"Tool: force_logout - Removed session {conn_id[:20]}... (user {user_id})")
    
    return (
        f"✅ **Force Logged Out**\n\n"
        f"• Connection: `{conn_id[:20]}...`\n"
        f"• User: `{user_id}`\n\n"
        f"Active sessions remaining: {len(_sessions)}"
    )


@mcp.tool()
async def logout_all_sessions() -> str:
    """
    Log out ALL active sessions across all connections.
    ⚠️ Use with caution - this will disconnect all users!
    Useful for demo reset or testing.
    """
    cleanup_expired()
    
    if not _sessions:
        return "ℹ️ No active sessions to log out."
    
    session_count = len(_sessions)
    users_logged_out = []
    
    for conn_id, session in _sessions.items():
        user_id = session.get("user_id", "unknown")
        users_logged_out.append(f"{user_id} ({conn_id[:12]}...)")
    
    # Clear all sessions
    _sessions.clear()
    
    logger.warning(f"Tool: logout_all_sessions - Cleared {session_count} sessions")
    
    result = (
        f"✅ **All Sessions Logged Out**\n\n"
        f"Removed {session_count} active session(s):\n\n"
    )
    
    for user in users_logged_out:
        result += f"• {user}\n"
    
    result += "\nAll users will need to re-authenticate."
    
    return result


@mcp.tool()
async def list_active_sessions() -> str:
    """
    List all currently active authenticated sessions.
    Shows connection IDs, user IDs, and session age.
    Useful for managing demo accounts and troubleshooting.
    """
    cleanup_expired()
    
    if not _sessions:
        return (
            "ℹ️ **No Active Sessions**\n\n"
            "No users are currently authenticated.\n"
            "Use authentication URL to log in."
        )
    
    result = f"👥 **Active Sessions** ({len(_sessions)} total)\n\n"
    
    # Sort by most recent first
    sorted_sessions = sorted(
        _sessions.items(),
        key=lambda x: x[1].get("timestamp", 0),
        reverse=True
    )
    
    for conn_id, session in sorted_sessions:
        user_id = session.get("user_id", "unknown")
        timestamp = session.get("timestamp", 0)
        expires_in = session.get("expires_in", TOKEN_EXPIRY_SECONDS)
        scope = session.get("scope", "N/A")
        
        # Calculate age and remaining time
        age_seconds = int(time.time() - timestamp)
        age_minutes = age_seconds // 60
        
        remaining_seconds = expires_in - age_seconds
        remaining_minutes = max(0, remaining_seconds // 60)
        
        result += f"**Connection:** `{conn_id[:20]}...`\n"
        result += f"• User: `{user_id}`\n"
        result += f"• Active for: {age_minutes} minutes\n"
        result += f"• Expires in: {remaining_minutes} minutes\n"
        result += f"• Scope: {scope}\n"
        result += f"• Status: {'✅ Active' if remaining_seconds > 0 else '⏰ Expired'}\n\n"
    
    result += (
        f"**Session Management:**\n"
        f"• Use `logout` to log out your current session\n"
        f"• Use `force_logout` with connection ID to log out a specific session\n"
        f"• Use `logout_all_sessions` to clear all sessions (demo reset)\n"
    )
    
    return result


@mcp.tool()
async def get_my_connection_id() -> str:
    """
    Get your current connection ID.
    Useful for identifying which session you're using during demos.
    """
    _, token_data, authenticated, connection_id = get_user_session()
    
    if not connection_id:
        return "❌ Unable to determine connection ID."
    
    result = f"🔑 **Your Connection ID**\n\n"
    result += f"• Full ID: `{connection_id}`\n"
    result += f"• Short ID: `{connection_id[:20]}...`\n\n"
    
    if authenticated and token_data:
        user_id = token_data.get("user_id", "unknown")
        timestamp = token_data.get("timestamp", 0)
        age_seconds = int(time.time() - timestamp)
        age_minutes = age_seconds // 60
        
        result += f"**Session Info:**\n"
        result += f"• Authenticated: ✅ Yes\n"
        result += f"• User: `{user_id}`\n"
        result += f"• Session age: {age_minutes} minutes\n"
    else:
        result += f"**Session Info:**\n"
        result += f"• Authenticated: ❌ No\n"
        result += f"• Log in to create a session\n"
    
    return result


@mcp.tool()
async def switch_user() -> str:
    """
    Log out and get a fresh authentication link to switch users.
    Convenience tool for demo scenarios where you need to quickly
    switch between different user accounts (student, instructor, admin).
    """
    token, token_data, authenticated, connection_id = get_user_session()
    
    old_user = "None"
    if authenticated and token_data:
        old_user = token_data.get("user_id", "unknown")
        if connection_id and connection_id in _sessions:
            del _sessions[connection_id]
            logger.info(f"Tool: switch_user - Logged out {old_user} from connection {connection_id[:20]}...")
    
    if not connection_id:
        connection_id = secrets.token_urlsafe(16)
    
    result = (
        f"🔄 **Switching Users**\n\n"
        f"• Previous user: `{old_user}`\n"
        f"• Connection: `{connection_id[:20]}...`\n\n"
        f"Click the link below to authenticate as a different user:\n\n"
    )
    
    result += get_auth_url(connection_id).replace("🔐 **Authentication Required**\n\n", "")
    
    return result


@mcp.tool()
async def demo_status() -> str:
    """
    Get a quick overview of the demo environment status.
    Shows active sessions, pending auths, and system health.
    Perfect for verifying your demo setup.
    """
    cleanup_expired()
    
    result = "📊 **Demo Environment Status**\n\n"
    
    # Active sessions
    result += f"**Active Sessions:** {len(_sessions)}\n"
    if _sessions:
        for conn_id, session in list(_sessions.items())[:5]:  # Show first 5
            user_id = session.get("user_id", "unknown")
            age = int(time.time() - session.get("timestamp", 0)) // 60
            result += f"  • {user_id} - {age}m ago\n"
        if len(_sessions) > 5:
            result += f"  • ...and {len(_sessions) - 5} more\n"
    
    result += f"\n**Pending OAuth Flows:** {len(_pending_auths)}\n"
    result += f"**Auth Codes Pending:** {len(_auth_codes)}\n"
    result += f"**Completed States (cache):** {len(_completed_states)}\n\n"
    
    # Configuration check
    result += "**Configuration:**\n"
    result += f"  • Blackboard URL: {'✅ Set' if BLACKBOARD_URL else '❌ Missing'}\n"
    result += f"  • App Key: {'✅ Set' if BLACKBOARD_APP_KEY else '❌ Missing'}\n"
    result += f"  • App Secret: {'✅ Set' if BLACKBOARD_APP_SECRET else '❌ Missing'}\n"
    result += f"  • Server URL: {'✅ Set' if SERVER_URL else '❌ Missing'}\n\n"
    
    # Quick actions
    result += "**Quick Actions:**\n"
    result += "  • `switch_user` - Log out and auth as different user\n"
    result += "  • `list_active_sessions` - See all logged in users\n"
    result += "  • `logout_all_sessions` - Reset demo (logout everyone)\n"
    result += "  • `check_auth_status` - Check your current auth status\n"
    
    return result


# Update the existing check_auth_status to include connection info
@mcp.tool()
async def check_auth_status() -> str:
    """Check your current authentication status with enhanced demo info"""
    cleanup_expired()
    
    token, token_data, authenticated, connection_id = get_user_session()
    
    logger.info(f"Tool: check_auth_status - connection {connection_id[:20] if connection_id else 'unknown'}...")
    logger.info(f"Tool: Total active sessions: {len(_sessions)}")
    
    if not authenticated or not token_data:
        result = "🔒 **Not Authenticated**\n\n"
        result += f"• Connection ID: `{connection_id[:20] if connection_id else 'unknown'}...`\n"
        result += f"• Active sessions: {len(_sessions)}\n\n"
        return result + get_auth_url(connection_id)
    
    timestamp = token_data.get("timestamp", 0)
    expires_in = token_data.get("expires_in", TOKEN_EXPIRY_SECONDS)
    elapsed = time.time() - timestamp
    remaining = expires_in - elapsed
    
    if remaining <= 0:
        if connection_id and connection_id in _sessions:
            del _sessions[connection_id]
        return "⏰ **Session Expired**\n\n" + get_auth_url(connection_id)
    
    user_id = token_data.get("user_id", "unknown")
    minutes_remaining = int(remaining / 60)
    minutes_active = int(elapsed / 60)
    
    return (
        f"✅ **Authenticated**\n\n"
        f"**Your Session:**\n"
        f"• User ID: `{user_id}`\n"
        f"• Connection: `{connection_id[:20] if connection_id else 'unknown'}...`\n"
        f"• Active for: {minutes_active} minutes\n"
        f"• Expires in: {minutes_remaining} minutes\n"
        f"• Scope: {token_data.get('scope', 'N/A')}\n\n"
        f"**System:**\n"
        f"• Total active sessions: {len(_sessions)}\n"
        f"• Use `list_active_sessions` to see all users\n"
        f"• Use `switch_user` to change accounts\n"
    )
