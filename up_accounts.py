from typing import Any
import httpx
import json
import requests
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("up-app")

# Constants
API_BASE = "https://api.up.com.au/api/v1"
USER_AGENT = "up-app/1.0"
UP_TOKEN = "XXXX"

async def make_request(url: str) -> dict[str, Any] | None:
    """Make a request to the API with proper error handling."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Authorization": f'Bearer {UP_TOKEN}'
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None



@mcp.tool()
async def up_accounts(id: str) -> str:
    """Get name from swapi api.

    Args:
        id: exact name match
    """
    url = f"{API_BASE}/accounts"
    data = await make_request(url)

    if not data:
        return "Unable to fetch data from API."

    #msg = format_msg(data)
    return data

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')
