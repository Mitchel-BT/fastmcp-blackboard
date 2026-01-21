"""
Authentication and token management for Blackboard MCP Server.
Handles OAuth flow and secure token storage.
"""
import os
import base64
import secrets
import time
import httpx
from urllib.parse import quote

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

_required_vars = ["BLACKBOARD_URL", "BLACKBOARD_APP_KEY", "BLACKBOARD_APP_SECRET", "SERVER_URL"]
_missing = [var for var in _required_vars if not os.environ.get(var)]
if _missing:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(_missing)}")


# ============================================================================
# TOKEN STORAGE
# In production, replace with Redis or database storage
# ============================================================================
_pending_auths = {}  # state -> OAuth flow data
_user_tokens = {}    # user_token -> blackboard credentials


def generate_user_token() -> str:
    """Generate a random opaque token"""
    return secrets.token_urlsafe(24)


def store_user_credentials(user_token: str, bb_access_token: str, bb_refresh_token: str,
                           user_id: str, expires_in: int):
    """Store Blackboard credentials mapped to our opaque user token"""
    _user_tokens[user_token] = {
        "bb_access_token": bb_access_token,
        "bb_refresh_token": bb_refresh_token,
        "bb_user_id": user_id,
        "bb_expires_in": expires_in,
        "obtained_at": time.time()
    }


def get_bb_token(user_token: str) -> str | None:
    """Get Blackboard access token for a user token"""
    creds = _user_tokens.get(user_token)
    if not creds:
        return None

    age = time.time() - creds["obtained_at"]
    if age > (creds["bb_expires_in"] - 300):
        # Token expired or expiring soon
        # TODO: Auto-refresh using bb_refresh_token
        return None

    return creds["bb_access_token"]


def get_user_info(user_token: str) -> dict | None:
    """Get user info for a token (without exposing BB credentials)"""
    creds = _user_tokens.get(user_token)
    if not creds:
        return None

    age = time.time() - creds["obtained_at"]
    return {
        "user_id": creds["bb_user_id"],
        "token_age_seconds": int(age),
        "expires_in_seconds": max(0, int(creds["bb_expires_in"] - age))
    }


def create_pending_auth() -> str:
    """Create a pending auth state and return the state token"""
    state = secrets.token_urlsafe(32)
    _pending_auths[state] = {"timestamp": time.time()}
    return state


def get_pending_auth(state: str) -> dict | None:
    """Get and remove pending auth data"""
    return _pending_auths.pop(state, None)


def get_blackboard_auth_url(state: str) -> str:
    """Generate Blackboard OAuth authorization URL"""
    callback_uri = f"{SERVER_URL}/auth/callback"
    return (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&redirect_uri={quote(callback_uri, safe='')}"
        f"&scope=read+write+offline"
        f"&state={state}"
    )


async def exchange_code_for_token(code: str) -> dict:
    """Exchange authorization code for Blackboard tokens"""
    credentials = f"{BLACKBOARD_APP_KEY}:{BLACKBOARD_APP_SECRET}"
    auth_header = base64.b64encode(credentials.encode()).decode()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
            headers={
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": f"{SERVER_URL}/auth/callback"
            }
        )

        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.text}")

        return response.json()
