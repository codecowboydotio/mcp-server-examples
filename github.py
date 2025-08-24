from typing import Any
import httpx
import json
import requests
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("sysdig-app")

# Constants
GITHUB_TOKEN="XXX"


@mcp.tool()
async def github_deploy(owner, repo, event_message):
    """Get name from swapi api.

    Args:
        id: exact name match
    """    

    #url = f"https://api.github.com/repos/{owner}/{repo}/dispatches"
    url = f"https://api.github.com/repos/{owner}/{repo}/dispatches"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f'Bearer {GITHUB_TOKEN}'
    }
    data = {
        'event_type': f'{event_message}'
    }
    
    query_answer = requests.post(url, headers=headers, json=data)
    query_response_code = query_answer.status_code
    if query_response_code  == 204:
        return "Please check github actions for the status of the deployment"
    else:
        return query_answer.text

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')
