from typing import Any
import httpx
import json
import requests
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("sysdig-app")

# Constants
API_BASE = "https://app.au1.sysdig.com/api"
USER_AGENT = "sysdig-app/1.0"
TOKEN = "XXX"

async def make_request(url: str) -> dict[str, Any] | None:
    """Make a request to the API with proper error handling."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Authorization": f'Bearer {TOKEN}'
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None



@mcp.tool()
async def sysdig(id: str) -> str:
    """Get name from swapi api.

    Args:
        id: exact name match
    """
    url = f"{API_BASE}/sage/sysql/generate?question={id}"
    data = await make_request(url)
    query = data.get('text', 'Unknown')
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Authorization": f'Bearer {TOKEN}'
    }
    query_url=f"{API_BASE}/sysql/v2/query?q={query}"
    query_answer = requests.get(query_url, headers=headers)
    query_response = json.loads(query_answer.text)

    if not data:
        return "Unable to fetch data from API."

    #msg = format_msg(data)
    return query_response

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')
