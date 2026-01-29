import os
from fastmcp import FastMCP, Context
from dotenv import load_dotenv
from auth import token_manager
from blackboard_client import BlackboardClient

load_dotenv()

mcp = FastMCP("Blackboard")

@mcp.tool()
async def get_auth_link(ctx: Context) -> str:
    """
    Get a link to authenticate with Blackboard.
    
    Returns:
        Instructions with authentication URL
    """
    # Create a temporary auth session
    auth_session_id = token_manager.create_auth_session()
    
    server_url = os.getenv("SERVER_URL")
    auth_url = f"{server_url}/auth/start?session={auth_session_id}"
    
    return f"""🔐 **Blackboard Authentication**

1. Click this link to log in: {auth_url}
2. Log in with your Blackboard credentials
3. Copy the code shown on the success page
4. Come back here and use: complete_auth("<paste code here>")

The link is valid for 30 minutes."""

@mcp.tool()
async def complete_auth(auth_code: str, ctx: Context) -> str:
    """
    Complete Blackboard authentication with the code from the browser.
    
    Args:
        auth_code: The authentication code from the success page
        
    Returns:
        Success or error message
    """
    mcp_session_id = ctx.session_id
    
    if not mcp_session_id:
        return "❌ Error: No MCP session ID available. Are you using HTTP transport?"
    
    # Link the auth session to this MCP session
    success = await token_manager.link_to_mcp_session(auth_code, mcp_session_id)
    
    if success:
        return f"""✅ **Authentication Complete!**

Your Blackboard account is now connected to this session.
Session ID: {mcp_session_id[:16]}...

You can now use:
- get_courses() - View your courses
- get_grades(course_id) - Check your grades
- And more!"""
    else:
        return """❌ **Authentication Failed**

The code may be invalid or expired. Please try again:
1. Use get_auth_link() to get a new link
2. Log in to Blackboard
3. Copy the new code
4. Use complete_auth("<new code>")"""

@mcp.tool()
async def get_courses(ctx: Context) -> str:
    """
    Get all your enrolled Blackboard courses.
    
    Returns:
        List of courses or error message
    """
    mcp_session_id = ctx.session_id
    
    if not mcp_session_id:
        return "❌ Error: No session ID available"
    
    # Get the Blackboard token for this session
    bb_token = await token_manager.get_token(mcp_session_id)
    
    if not bb_token:
        return """⚠️ **Not Authenticated**

Please authenticate first:
1. Use get_auth_link() to start
2. Follow the authentication steps"""
    
    try:
        # Create Blackboard client and fetch courses
        client = BlackboardClient(
            base_url=os.getenv("BLACKBOARD_URL"),
            app_key=os.getenv("BLACKBOARD_APP_KEY"),
            app_secret=os.getenv("BLACKBOARD_APP_SECRET")
        )
        
        courses = await client.get_courses(bb_token["access_token"])
        
        # Format the response
        result = f"📚 **Your Courses** (Session: {mcp_session_id[:16]}...)\n\n"
        
        if not courses:
            return result + "No courses found."
        
        for course in courses:
            result += f"• {course.get('name', 'Unknown')} ({course.get('courseId', 'N/A')})\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error fetching courses: {str(e)}"

@mcp.tool()
async def check_session_status(ctx: Context) -> str:
    """
    Check your current authentication status.
    
    Returns:
        Session information
    """
    mcp_session_id = ctx.session_id
    
    if not mcp_session_id:
        return "❌ No MCP session ID available"
    
    bb_token = await token_manager.get_token(mcp_session_id)
    is_authenticated = bb_token is not None
    
    active_sessions = token_manager.get_session_count()
    pending_auths = token_manager.get_pending_auth_count()
    
    return f"""📊 **Session Status**

MCP Session ID: {mcp_session_id[:16]}...
Authenticated: {'✅ Yes' if is_authenticated else '❌ No'}

Server Stats:
- Active Sessions: {active_sessions}
- Pending Auths: {pending_auths}"""

@mcp.tool()
async def logout(ctx: Context) -> str:
    """
    Log out and remove your stored Blackboard credentials.
    
    Returns:
        Confirmation message
    """
    mcp_session_id = ctx.session_id
    
    if not mcp_session_id:
        return "❌ No session ID available"
    
    await token_manager.delete_token(mcp_session_id)
    
    return f"""✅ **Logged Out Successfully**

Your Blackboard credentials have been removed from session {mcp_session_id[:16]}...

To reconnect, use get_auth_link()"""

if __name__ == "__main__":
    # Run the MCP server
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
