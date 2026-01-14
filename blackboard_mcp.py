"""
Blackboard MCP Server - Minimal Test Version
Let's first verify the server starts, then add OAuth
"""

from fastmcp import FastMCP

# Create basic server without auth first
mcp = FastMCP(name="Blackboard")


@mcp.tool()
def hello(name: str = "World") -> str:
    """Simple test tool to verify server is working"""
    return f"Hello, {name}! The Blackboard MCP server is running."


@mcp.tool()
def server_info() -> str:
    """Get server information"""
    return "Blackboard MCP Server v0.1 - Test deployment"
