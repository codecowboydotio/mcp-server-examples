from datetime import datetime
import json
import requests
import os
import sys
import asyncio
from typing import Optional
from fastmcp import Client



try:
 api_key=os.getenv("API_KEY")
 if obsidian_api_key is None:
  raise ValueError("API_KEY environment variable is not set")
 api_endpoint=os.getenv("API_ENDPOINT")
except ValueError as e:
 print(f"Error: {e}") 

url = api_endpoint+"/mcp/"

async def main():
 try:
  async with Client(url, auth=api_key) as client:
    
   tools = await client.list_tools()
   for item in tools:
    print(item.name)
    print(item.description)
    print("\n")
 except Exception as e:
  print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)

if __name__ == '__main__':
 asyncio.run(main())
