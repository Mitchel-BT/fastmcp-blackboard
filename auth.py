import os
import json
import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from typing import Optional, Dict

class TokenManager:
    """Manages encrypted storage of Blackboard tokens per MCP session"""
    
    def __init__(self):
        key = os.getenv("TOKEN_ENCRYPTION_KEY")
        if not key:
            raise ValueError("TOKEN_ENCRYPTION_KEY environment variable must be set")
        
        self.cipher = Fernet(key.encode())
        
        # Session-based token storage: {mcp_session_id: encrypted_token}
        # In production, replace with Redis or PostgreSQL
        self._session_tokens: Dict[str, str] = {}
        
        # Temporary auth sessions for OAuth flow: {auth_session_id: session_data}
        self._auth_sessions: Dict[str, dict] = {}
        
        print("✅ TokenManager initialized")
    
    def create_auth_session(self) -> str:
        """
        Create a temporary auth session for the OAuth flow.
        Returns a unique session ID that the user will use to complete auth.
        """
        auth_session_id = secrets.token_urlsafe(32)
        self._auth_sessions[auth_session_id] = {
            "created_at": datetime.now(),
            "token": None,
            "status": "pending"
        }
        print(f"🔑 Created auth session: {auth_session_id[:16]}...")
        return auth_session_id
    
    async def store_auth_token(self, auth_session_id: str, blackboard_token: dict):
        """
        Store the Blackboard token in a temporary auth session.
        This is called after the user logs into Blackboard.
        """
        if auth_session_id not in self._auth_sessions:
            raise ValueError(f"Invalid auth session ID: {auth_session_id[:16]}...")
        
        self._auth_sessions[auth_session_id]["token"] = blackboard_token
        self._auth_sessions[auth_session_id]["status"] = "completed"
        print(f"💾 Stored Blackboard token in auth session: {auth_session_id[:16]}...")
    
    async def link_to_mcp_session(self, auth_session_id: str, mcp_session_id: str) -> bool:
        """
        Link a completed auth session to an MCP session.
        This associates the Blackboard token with the user's MCP session.
        """
        if auth_session_id not in self._auth_sessions:
            print(f"❌ Auth session not found: {auth_session_id[:16]}...")
            return False
        
        auth_session = self._auth_sessions[auth_session_id]
        
        if auth_session["status"] != "completed" or not auth_session["token"]:
            print(f"❌ Auth session not completed: {auth_session_id[:16]}...")
            return False
        
        # Encrypt the token
        token_json = json.dumps(auth_session["token"])
        encrypted = self.cipher.encrypt(token_json.encode())
        
        # Store encrypted token for this MCP session
        self._session_tokens[mcp_session_id] = encrypted.decode()
        
        # Clean up the temporary auth session
        del self._auth_sessions[auth_session_id]
        
        print(f"✅ Linked Blackboard token to MCP session: {mcp_session_id[:16]}...")
        return True
    
    async def get_token(self, mcp_session_id: str) -> Optional[dict]:
        """
        Retrieve the Blackboard token for an MCP session.
        Returns None if no token is stored for this session.
        """
        if not mcp_session_id:
            print("❌ No MCP session ID provided")
            return None
        
        encrypted = self._session_tokens.get(mcp_session_id)
        
        if not encrypted:
            print(f"⚠️ No token found for session: {mcp_session_id[:16]}...")
            return None
        
        # Decrypt the token
        decrypted = self.cipher.decrypt(encrypted.encode())
        token = json.loads(decrypted)
        print(f"🔓 Retrieved token for session: {mcp_session_id[:16]}...")
        return token
    
    async def delete_token(self, mcp_session_id: str):
        """Remove the Blackboard token for an MCP session"""
        if mcp_session_id in self._session_tokens:
            del self._session_tokens[mcp_session_id]
            print(f"🗑️ Deleted token for session: {mcp_session_id[:16]}...")
    
    def get_session_count(self) -> int:
        """Get the number of active sessions (for testing/monitoring)"""
        return len(self._session_tokens)
    
    def get_pending_auth_count(self) -> int:
        """Get the number of pending auth sessions (for testing/monitoring)"""
        return len(self._auth_sessions)

# Global token manager instance
token_manager = TokenManager()
