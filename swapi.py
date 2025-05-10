from typing import Any
import httpx
import json
import requests
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("swapi")

# Constants
API_BASE = "http://10.1.1.150:3000"
USER_AGENT = "swapi-app/1.0"


async def make_request(url: str) -> dict[str, Any] | None:
    """Make a request to the API with proper error handling."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None


def format_msg(json_string):
    """Format an alert feature into a readable string."""
    props = json_string
    homeworld=json_string['homeworld']
    homeworld_url="http://10.1.1.150:3000/planets/" + str(homeworld)
    homeworld_name = requests.get(homeworld_url)
    homeworld_json=json.loads(homeworld_name.text)
    #print (homeworld_name.text)

    return f"""
Name: {props.get('name', 'Unknown')}
Gender: {props.get('gender', 'Unknown')}
Hair Colour: {props.get('hair_color', 'Unknown')}
Homeworld: {homeworld_json.get('name', 'Unknown')}
"""


@mcp.tool()
async def get_swapi_character(id: str) -> str:
    """Get name from swapi api.

    Args:
        id: exact name match
    """
    url = f"{API_BASE}/people/{id}"
    data = await make_request(url)

    if not data:
        return "Unable to fetch data from API."

    #alerts = [format_alert(feature) for feature in data["features"]]
    msg = format_msg(data)
    #return "\n---\n".join(msg)
    return msg

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')
