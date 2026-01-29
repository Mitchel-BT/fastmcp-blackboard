async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict:
    """
    Exchange authorization code for access token.
    
    Args:
        code: Authorization code from Blackboard
        redirect_uri: The redirect URI used in the auth request
        
    Returns:
        dict: Token response with access_token, refresh_token, etc.
    """
    token_url = f"{self.base_url}/learn/api/public/v1/oauth2/token"
    
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            token_url,
            auth=(self.app_key, self.app_secret),
            data=data
        )
        
        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.text}")
        
        return response.json()
