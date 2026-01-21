"""
Blackboard MCP Server with Persistent Authentication

Authentication flow:
1. User calls any tool -> gets auth link if not authenticated
2. User completes OAuth with Blackboard
3. Server stores Blackboard tokens in Redis, keyed by a generated session ID
4. Server issues a signed JWT containing the session ID
5. Claude receives this JWT and passes it as Bearer token on all subsequent requests
6. Server validates JWT, extracts session ID, retrieves Blackboard tokens from Redis
"""
import os
import json
import base64
import secrets
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from urllib.parse import quote
from typing import Optional

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from fastmcp.server.dependencies import get_http_request
from starlette.responses import RedirectResponse, JSONResponse, HTMLResponse
from starlette.requests import Request
from starlette.routing import Route

# ============================================================================
# CONFIGURATION
# ============================================================================
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")
JWT_SECRET = os.environ.get("JWT_SECRET")  # Secret for signing session JWTs
REDIS_URL = os.environ.get("UPSTASH_REDIS_REST_URL")  # e.g., redis://localhost:6379

# Validate required environment variables
_required_vars = ["BLACKBOARD_URL", "BLACKBOARD_APP_KEY", "BLACKBOARD_APP_SECRET", 
                  "SERVER_URL", "JWT_SECRET"]
_missing = [var for var in _required_vars if not os.environ.get(var)]
if _missing:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(_missing)}")

# ============================================================================
# STORAGE BACKEND (Redis or In-Memory fallback)
# ============================================================================

class TokenStorage:
    """Abstract interface for token storage"""
    async def store(self, session_id: str, data: dict, ttl_seconds: int = 86400) -> bool:
        raise NotImplementedError
    
    async def retrieve(self, session_id: str) -> Optional[dict]:
        raise NotImplementedError
    
    async def delete(self, session_id: str) -> bool:
        raise NotImplementedError


class RedisTokenStorage(TokenStorage):
    """Redis-backed persistent storage"""
    def __init__(self, redis_url: str):
        import redis.asyncio as redis
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.prefix = "blackboard:session:"
    
    async def store(self, session_id: str, data: dict, ttl_seconds: int = 86400) -> bool:
        key = f"{self.prefix}{session_id}"
        await self.redis.setex(key, ttl_seconds, json.dumps(data))
        return True
    
    async def retrieve(self, session_id: str) -> Optional[dict]:
        key = f"{self.prefix}{session_id}"
        data = await self.redis.get(key)
        return json.loads(data) if data else None
    
    async def delete(self, session_id: str) -> bool:
        key = f"{self.prefix}{session_id}"
        await self.redis.delete(key)
        return True


class InMemoryTokenStorage(TokenStorage):
    """In-memory storage (for development only - tokens lost on restart)"""
    def __init__(self):
        self._store = {}
    
    async def store(self, session_id: str, data: dict, ttl_seconds: int = 86400) -> bool:
        self._store[session_id] = {
            "data": data,
            "expires_at": time.time() + ttl_seconds
        }
        return True
    
    async def retrieve(self, session_id: str) -> Optional[dict]:
        entry = self._store.get(session_id)
        if not entry:
            return None
        if time.time() > entry["expires_at"]:
            del self._store[session_id]
            return None
        return entry["data"]
    
    async def delete(self, session_id: str) -> bool:
        self._store.pop(session_id, None)
        return True


# Initialize storage
if REDIS_URL:
    storage = RedisTokenStorage(REDIS_URL)
    print("[Storage] Using Redis for token persistence")
else:
    storage = InMemoryTokenStorage()
    print("[Storage] WARNING: Using in-memory storage. Tokens will not persist across restarts.")


# ============================================================================
# SIMPLE JWT IMPLEMENTATION (no external dependencies)
# ============================================================================

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def base64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def create_session_jwt(session_id: str, user_id: str = None, expires_hours: int = 24 * 7) -> str:
    """Create a signed JWT containing the session ID"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sid": session_id,  # session ID to look up Blackboard tokens
        "uid": user_id,     # Blackboard user ID (informational)
        "iat": int(time.time()),
        "exp": int(time.time() + expires_hours * 3600)
    }
    
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    
    return f"{message}.{signature_b64}"

def verify_session_jwt(token: str) -> Optional[dict]:
    """Verify JWT and return payload, or None if invalid"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).digest()
        actual_sig = base64url_decode(signature_b64)
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        
        # Decode and check expiration
        payload = json.loads(base64url_decode(payload_b64))
        if payload.get("exp", 0) < time.time():
            return None
        
        return payload
    except Exception:
        return None


# ============================================================================
# PENDING AUTH FLOWS (short-lived, in-memory is fine)
# ============================================================================
_pending_auths = {}


# ============================================================================
# BLACKBOARD AUTH PROVIDER
# ============================================================================

class BlackboardAuthProvider(AuthProvider):
    """
    Custom auth provider that:
    1. Validates incoming Bearer tokens (our session JWTs)
    2. Provides OAuth endpoints for Blackboard authentication
    """
    
    def get_routes(self) -> list[Route]:
        """Return OAuth-related routes"""
        return [
            Route("/.well-known/oauth-protected-resource", self._protected_resource_metadata, methods=["GET"]),
            Route("/.well-known/oauth-authorization-server", self._authorization_server_metadata, methods=["GET"]),
            Route("/oauth/authorize", self._oauth_authorize, methods=["GET"]),
            Route("/oauth/callback", self._oauth_callback, methods=["GET"]),
            Route("/oauth/token", self._oauth_token, methods=["POST"]),
            Route("/oauth/register", self._client_registration, methods=["POST"]),
            Route("/auth/status", self._auth_status, methods=["GET"]),
        ]
    
    async def _protected_resource_metadata(self, request: Request):
        """Tell MCP clients how to authenticate"""
        return JSONResponse({
            "resource": SERVER_URL,
            "authorization_servers": [SERVER_URL]
        })
    
    async def _authorization_server_metadata(self, request: Request):
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        return JSONResponse({
            "issuer": SERVER_URL,
            "authorization_endpoint": f"{SERVER_URL}/oauth/authorize",
            "token_endpoint": f"{SERVER_URL}/oauth/token",
            "registration_endpoint": f"{SERVER_URL}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "scopes_supported": ["read", "write", "offline"],
            "response_modes_supported": ["query"],
        })
    
    async def _client_registration(self, request: Request):
        """Dynamic Client Registration endpoint (RFC 7591) for MCP clients"""
        try:
            body = await request.json()
        except:
            body = {}
        
        # Generate a client ID for this MCP client
        client_id = secrets.token_urlsafe(16)
        client_name = body.get("client_name", "Unknown Client")
        redirect_uris = body.get("redirect_uris", [])
        
        print(f"[DCR] Registering client: {client_name}, redirect_uris: {redirect_uris}")
        
        # Store client registration (optional - for validation later)
        # For now we accept any client since we validate via the OAuth flow
        
        return JSONResponse({
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        })
    
    async def _oauth_authorize(self, request: Request):
        """OAuth authorization - redirects to Blackboard"""
        client_id = request.query_params.get("client_id")
        redirect_uri = request.query_params.get("redirect_uri")
        state = request.query_params.get("state")
        code_challenge = request.query_params.get("code_challenge")
        
        print(f"[OAuth] Authorization request from client: {client_id}")
        
        # Generate our state to track this flow
        our_state = secrets.token_urlsafe(32)
        
        _pending_auths[our_state] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "timestamp": time.time()
        }
        
        # Redirect to Blackboard OAuth
        callback_uri = f"{SERVER_URL}/oauth/callback"
        blackboard_auth_url = (
            f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
            f"?response_type=code"
            f"&client_id={BLACKBOARD_APP_KEY}"
            f"&redirect_uri={quote(callback_uri, safe='')}"
            f"&scope=read+write+offline"
            f"&state={our_state}"
        )
        
        return RedirectResponse(blackboard_auth_url)
    
    async def _oauth_callback(self, request: Request):
        """Callback from Blackboard after user authenticates"""
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")
        
        print(f"[Callback] Received - code: {bool(code)}, state: {state[:16] if state else None}...")
        
        if error:
            return HTMLResponse(f"<h1>Authentication Error</h1><p>{error}</p>", status_code=400)
        
        if not code or not state:
            return HTMLResponse("<h1>Error</h1><p>Missing parameters</p>", status_code=400)
        
        original = _pending_auths.pop(state, None)
        if not original:
            print(f"[Callback] State not found. Active states: {list(_pending_auths.keys())[:3]}")
            return HTMLResponse("<h1>Error</h1><p>Invalid or expired session</p>", status_code=400)
        
        # Exchange code for Blackboard tokens
        try:
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
                        "redirect_uri": f"{SERVER_URL}/oauth/callback"
                    }
                )
                
                if response.status_code != 200:
                    return HTMLResponse(f"<h1>Token Error</h1><p>{response.text}</p>", status_code=500)
                
                bb_tokens = response.json()
            
            # Generate session ID and store Blackboard tokens
            session_id = secrets.token_urlsafe(32)
            
            await storage.store(session_id, {
                "access_token": bb_tokens["access_token"],
                "refresh_token": bb_tokens.get("refresh_token"),
                "token_type": bb_tokens.get("token_type", "bearer"),
                "expires_in": bb_tokens.get("expires_in", 3600),
                "user_id": bb_tokens.get("user_id"),
                "obtained_at": time.time()
            }, ttl_seconds=86400 * 30)  # 30 day TTL
            
            # Generate our auth code that maps to this session
            our_code = secrets.token_urlsafe(32)
            _pending_auths[our_code] = {
                "session_id": session_id,
                "user_id": bb_tokens.get("user_id"),
                "timestamp": time.time(),
                "type": "auth_code"  # Mark this as an auth code, not a state
            }
            
            print(f"[Callback] Created auth code {our_code[:16]}... for session {session_id[:16]}...")
            print(f"[Callback] Original redirect_uri: {original.get('redirect_uri')}")
            print(f"[Callback] Original state: {original.get('state')}")
            
            # Redirect back to Claude with our code
            # Claude's callback URL should be in redirect_uri from the original auth request
            if original.get("redirect_uri"):
                redirect_url = f"{original['redirect_uri']}?code={our_code}"
                if original.get("state"):
                    redirect_url += f"&state={original['state']}"
                print(f"[Callback] Redirecting to: {redirect_url[:100]}...")
                return RedirectResponse(redirect_url)
            else:
                # Fallback for manual testing - show success page
                return HTMLResponse(f"""
                    <html><body style="font-family: sans-serif; padding: 2rem; text-align: center;">
                    <h1>✅ Authentication Successful!</h1>
                    <p>You can close this window and return to Claude.</p>
                    <p style="color: #666; font-size: 0.9em;">Session ID: {session_id[:16]}...</p>
                    </body></html>
                """)
                
        except Exception as e:
            print(f"[Callback ERROR] {e}")
            return HTMLResponse(f"<h1>Error</h1><p>{str(e)}</p>", status_code=500)
    
    async def _oauth_token(self, request: Request):
        """Token endpoint - exchanges our code for a session JWT"""
        form = await request.form()
        code = form.get("code")
        grant_type = form.get("grant_type")
        
        print(f"[Token] Request - grant_type: {grant_type}, code: {code[:16] if code else None}...")
        
        if grant_type == "refresh_token":
            refresh_token = form.get("refresh_token")
            payload = verify_session_jwt(refresh_token)
            if not payload:
                print("[Token] Refresh failed - invalid JWT")
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            
            session_data = await storage.retrieve(payload["sid"])
            if not session_data:
                print(f"[Token] Refresh failed - session {payload['sid'][:16]}... not found")
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            
            # Issue new JWT
            new_jwt = create_session_jwt(payload["sid"], payload.get("uid"))
            print(f"[Token] Refreshed token for session {payload['sid'][:16]}...")
            return JSONResponse({
                "access_token": new_jwt,
                "token_type": "bearer",
                "expires_in": 86400 * 7,
                "refresh_token": new_jwt
            })
        
        if not code:
            return JSONResponse({"error": "missing_code"}, status_code=400)
        
        auth_data = _pending_auths.pop(code, None)
        if not auth_data or auth_data.get("type") != "auth_code":
            print(f"[Token] Invalid code - not found or wrong type")
            return JSONResponse({"error": "invalid_code"}, status_code=400)
        
        if "session_id" not in auth_data:
            print(f"[Token] Invalid code - no session_id")
            return JSONResponse({"error": "invalid_code"}, status_code=400)
        
        # Issue session JWT
        session_jwt = create_session_jwt(
            auth_data["session_id"],
            auth_data.get("user_id")
        )
        
        print(f"[Token] Issued JWT for session {auth_data['session_id'][:16]}..., user {auth_data.get('user_id')}")
        
        return JSONResponse({
            "access_token": session_jwt,
            "token_type": "bearer",
            "expires_in": 86400 * 7,  # 7 days
            "refresh_token": session_jwt,  # Can use same JWT to refresh
            "scope": "read write offline"
        })
    
    async def _auth_status(self, request: Request):
        """Debug endpoint to check auth status"""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"authenticated": False, "reason": "No bearer token"})
        
        token = auth_header[7:]
        payload = verify_session_jwt(token)
        if not payload:
            return JSONResponse({"authenticated": False, "reason": "Invalid or expired JWT"})
        
        session_data = await storage.retrieve(payload["sid"])
        if not session_data:
            return JSONResponse({"authenticated": False, "reason": "Session not found in storage"})
        
        return JSONResponse({
            "authenticated": True,
            "user_id": session_data.get("user_id"),
            "session_id": payload["sid"][:16] + "...",
            "bb_token_age_seconds": int(time.time() - session_data.get("obtained_at", 0))
        })


# ============================================================================
# HELPER: Get authenticated Blackboard client
# ============================================================================

async def get_blackboard_token_from_request(request: Request) -> Optional[str]:
    """Extract session JWT from request, validate, and return Blackboard access token"""
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header.startswith("Bearer "):
        return None
    
    token = auth_header[7:]
    payload = verify_session_jwt(token)
    
    if not payload:
        return None
    
    session_data = await storage.retrieve(payload["sid"])
    if not session_data:
        return None
    
    # Check if Blackboard token needs refresh
    token_age = time.time() - session_data.get("obtained_at", 0)
    expires_in = session_data.get("expires_in", 3600)
    
    if token_age > (expires_in - 300) and session_data.get("refresh_token"):
        # Refresh the Blackboard token
        refreshed = await refresh_blackboard_token(payload["sid"], session_data)
        if refreshed:
            return refreshed["access_token"]
    
    return session_data.get("access_token")


async def refresh_blackboard_token(session_id: str, session_data: dict) -> Optional[dict]:
    """Refresh Blackboard access token using refresh token"""
    try:
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
                    "grant_type": "refresh_token",
                    "refresh_token": session_data["refresh_token"]
                }
            )
            
            if response.status_code != 200:
                return None
            
            new_tokens = response.json()
            
            # Update stored session
            updated_data = {
                **session_data,
                "access_token": new_tokens["access_token"],
                "refresh_token": new_tokens.get("refresh_token", session_data["refresh_token"]),
                "expires_in": new_tokens.get("expires_in", 3600),
                "obtained_at": time.time()
            }
            
            await storage.store(session_id, updated_data, ttl_seconds=86400 * 30)
            return updated_data
            
    except Exception as e:
        print(f"[Refresh ERROR] {e}")
        return None


async def make_blackboard_request(endpoint: str, method: str = "GET", **kwargs) -> dict:
    """Make authenticated request to Blackboard API"""
    request = get_http_request()
    bb_token = await get_blackboard_token_from_request(request)
    
    if not bb_token:
        # Return auth required response with link
        return {
            "error": "authentication_required",
            "message": "Please authenticate with Blackboard first.",
            "instructions": "Your MCP client should handle OAuth automatically. If not, visit the authorization endpoint.",
            "auth_url": f"{SERVER_URL}/oauth/authorize"
        }
    
    url = f"{BLACKBOARD_URL}/learn/api/public/v1/{endpoint}"
    headers = {
        "Authorization": f"Bearer {bb_token}",
        **kwargs.pop("headers", {})
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(method, url, headers=headers, **kwargs)
            
            if response.status_code == 401:
                return {
                    "error": "authentication_required",
                    "message": "Your Blackboard session has expired. Please re-authenticate.",
                    "auth_url": f"{SERVER_URL}/oauth/authorize"
                }
            
            response.raise_for_status()
            return response.json()
            
    except httpx.HTTPStatusError as e:
        return {"error": "api_error", "status": e.response.status_code, "details": e.response.text}
    except Exception as e:
        return {"error": "request_failed", "message": str(e)}


# ============================================================================
# MCP SERVER
# ============================================================================

mcp = FastMCP("Blackboard", auth=BlackboardAuthProvider())


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp.tool()
async def get_my_courses() -> dict:
    """Get all courses you are enrolled in on Blackboard."""
    result = await make_blackboard_request("users/me/courses")
    
    if isinstance(result, dict) and result.get("error"):
        return result
    
    if isinstance(result, dict) and "results" in result:
        memberships = result["results"]
        courses = []
        for m in memberships:
            courses.append({
                "courseId": m.get("courseId"),
                "role": m.get("courseRoleId"),
                "availability": m.get("availability", {}).get("available"),
                "created": m.get("created")
            })
        return {"success": True, "courses": courses, "count": len(courses)}
    
    return result


@mcp.tool()
async def get_course_assignments(course_id: str) -> dict:
    """
    Get assignments for a specific course.
    
    Args:
        course_id: The course ID from get_my_courses (e.g., "_123_1")
    """
    result = await make_blackboard_request(f"courses/{course_id}/contents")
    
    if isinstance(result, dict) and result.get("error"):
        return result
    
    return result


@mcp.tool()
async def get_my_profile() -> dict:
    """Get your Blackboard user profile information."""
    return await make_blackboard_request("users/me")


@mcp.tool()
async def check_auth_status() -> dict:
    """Check if you're authenticated with Blackboard."""
    request = get_http_request()
    bb_token = await get_blackboard_token_from_request(request)
    
    if bb_token:
        return {
            "authenticated": True,
            "message": "You are authenticated with Blackboard."
        }
    else:
        return {
            "authenticated": False,
            "message": "Not authenticated. Your MCP client should prompt for OAuth.",
            "manual_auth_url": f"{SERVER_URL}/oauth/authorize"
        }
