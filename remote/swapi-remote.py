from typing import Any
import httpx
import os
import logging
from logging.handlers import RotatingFileHandler
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
import mcp.server.stdio

# Constants from environment variables with defaults
API_BASE = os.getenv("SWAPI_API_BASE", "http://10.1.1.150:3000")
USER_AGENT = os.getenv("USER_AGENT", "swapi-app/1.0")
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8443"))
API_KEY = os.getenv("MCP_API_KEY")

# SSL/TLS Configuration
SSL_CERTFILE = os.getenv("SSL_CERTFILE", "cert.pem")
SSL_KEYFILE = os.getenv("SSL_KEYFILE", "key.pem")
SSL_CA_CERTS = os.getenv("SSL_CA_CERTS")
USE_SSL = os.getenv("USE_SSL", "true").lower() == "true"

# CORS settings
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# Logging Configuration
LOG_FILE = os.getenv("LOG_FILE", "swapi-mcp.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "10485760"))  # 10MB default
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))
LOG_TO_CONSOLE = os.getenv("LOG_TO_CONSOLE", "true").lower() == "true"
LOG_TO_FILE = os.getenv("LOG_TO_FILE", "true").lower() == "true"

# Configure logging
def setup_logging():
    """Configure logging with file and console handlers."""
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    
    # Remove existing handlers
    logger.handlers = []
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    if LOG_TO_CONSOLE:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler with rotation
    if LOG_TO_FILE:
        try:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(LOG_FILE)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = RotatingFileHandler(
                LOG_FILE,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT
            )
            file_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
            logger.info(f"Logging to file: {LOG_FILE}")
            logger.info(f"Log rotation: {LOG_MAX_BYTES} bytes, {LOG_BACKUP_COUNT} backups")
        except Exception as e:
            logger.error(f"Failed to setup file logging: {e}")
    
    return logger

# Setup logging
logger = setup_logging()

# Initialize MCP Server
server = Server("swapi")


async def make_request(url: str) -> dict[str, Any] | None:
    """Make a request to the API with proper error handling."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"Making request to: {url}")
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            logger.info(f"Successfully fetched data from: {url}")
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code} for URL: {url}")
            return None
        except httpx.TimeoutException:
            logger.error(f"Timeout error for URL: {url}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error for URL {url}: {str(e)}")
            return None


async def format_msg(json_string: dict[str, Any]) -> str:
    """Format character data into a readable string (async version)."""
    props = json_string
    homeworld = json_string.get('homeworld')
    
    if not homeworld:
        logger.warning("No homeworld found in character data")
        homeworld_name = "Unknown"
    else:
        homeworld_url = f"{API_BASE}/planets/{homeworld}"
        logger.info(f"Fetching homeworld data from: {homeworld_url}")
        homeworld_data = await make_request(homeworld_url)
        homeworld_name = homeworld_data.get('name', 'Unknown') if homeworld_data else 'Unknown'

    return f"""
Name: {props.get('name', 'Unknown')}
Gender: {props.get('gender', 'Unknown')}
Hair Colour: {props.get('hair_color', 'Unknown')}
Homeworld: {homeworld_name}
"""


# Register tools with the server
@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="get_swapi_character",
            description="Get character information from SWAPI",
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Character ID (numeric string)"
                    }
                },
                "required": ["id"]
            }
        ),
        Tool(
            name="get_all_swapi_people",
            description="Get all people from SWAPI",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls."""
    logger.info(f"Tool called: {name} with arguments: {arguments}")
    
    if name == "get_swapi_character":
        character_id = arguments.get("id")
        logger.info(f"Fetching character with ID: {character_id}")
        url = f"{API_BASE}/people/{character_id}"
        data = await make_request(url)

        if not data:
            logger.warning(f"No data found for character ID: {character_id}")
            return [TextContent(type="text", text="Unable to fetch data from API.")]

        msg = await format_msg(data)
        logger.info(f"Successfully formatted character data for ID: {character_id}")
        return [TextContent(type="text", text=msg)]
    
    elif name == "get_all_swapi_people":
        logger.info("Fetching all people from SWAPI")
        url = f"{API_BASE}/people/"
        data = await make_request(url)

        if not data:
            logger.warning("Failed to fetch all people data")
            return [TextContent(type="text", text="Unable to fetch data from API.")]

        logger.info(f"Successfully fetched {len(data)} people")
        import json
        return [TextContent(type="text", text=json.dumps(data, indent=2))]
    
    else:
        raise ValueError(f"Unknown tool: {name}")


def validate_ssl_files():
    """Validate that SSL certificate and key files exist."""
    if not USE_SSL:
        return True
    
    if not os.path.exists(SSL_CERTFILE):
        logger.error(f"SSL certificate file not found: {SSL_CERTFILE}")
        return False
    
    if not os.path.exists(SSL_KEYFILE):
        logger.error(f"SSL key file not found: {SSL_KEYFILE}")
        return False
    
    if SSL_CA_CERTS and not os.path.exists(SSL_CA_CERTS):
        logger.error(f"SSL CA certs file not found: {SSL_CA_CERTS}")
        return False
    
    logger.info(f"SSL certificate: {SSL_CERTFILE}")
    logger.info(f"SSL key: {SSL_KEYFILE}")
    if SSL_CA_CERTS:
        logger.info(f"SSL CA certs: {SSL_CA_CERTS}")
    
    return True


if __name__ == "__main__":
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.requests import Request
    from starlette.middleware.cors import CORSMiddleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse
    
    logger.info("=" * 80)
    logger.info("Starting SWAPI MCP Server")
    logger.info("=" * 80)
    
    # Log configuration
    logger.info("Configuration:")
    logger.info(f"  API Base: {API_BASE}")
    logger.info(f"  Server Host: {SERVER_HOST}")
    logger.info(f"  Server Port: {SERVER_PORT}")
    logger.info(f"  SSL Enabled: {USE_SSL}")
    logger.info(f"  CORS Origins: {CORS_ORIGINS}")
    logger.info(f"  Log Level: {LOG_LEVEL}")
    logger.info(f"  Log File: {LOG_FILE if LOG_TO_FILE else 'Disabled'}")
    logger.info(f"  Log to Console: {LOG_TO_CONSOLE}")
    logger.info(f"  API Key Auth: {'Enabled' if API_KEY else 'Disabled'}")
    
    # Validate SSL configuration
    if USE_SSL and not validate_ssl_files():
        logger.error("SSL validation failed. Exiting.")
        exit(1)
    
    # Create SSE transport
    sse = SseServerTransport("/messages")
    
    # SSE endpoint handler
    async def handle_sse(request: Request):
        logger.debug(f"SSE connection from {request.client.host}")
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send
        ) as (read_stream, write_stream):
            # Run the server with the streams
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )
    
    # Messages endpoint handler
    async def handle_messages(request: Request):
        logger.debug(f"Message received from {request.client.host}")
        return await sse.handle_post_message(
            request.scope,
            request.receive,
            request._send
        )
    
    # Create Starlette app
    app = Starlette(
        debug=False,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Route("/messages", endpoint=handle_messages, methods=["POST"]),
        ],
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add API key middleware if configured
    if API_KEY:
        class APIKeyMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                provided_key = request.headers.get("X-API-Key")
                if provided_key != API_KEY:
                    logger.warning(f"Invalid API key attempt from {request.client.host}")
                    return JSONResponse(
                        status_code=401,
                        content={"error": "Invalid or missing API key"}
                    )
                return await call_next(request)
        
        app.add_middleware(APIKeyMiddleware)
        logger.info("API key authentication middleware added")
    else:
        logger.warning("Running without API key authentication - not recommended for production")
    
    protocol = "https" if USE_SSL else "http"
    logger.info(f"Server will start on {protocol}://{SERVER_HOST}:{SERVER_PORT}")
    
    if not USE_SSL:
        logger.warning("Running in HTTP mode (not secure) - use HTTPS in production")
    
    # Configure SSL
    ssl_config = {}
    if USE_SSL:
        ssl_config = {
            "ssl_certfile": SSL_CERTFILE,
            "ssl_keyfile": SSL_KEYFILE,
        }
        if SSL_CA_CERTS:
            ssl_config["ssl_ca_certs"] = SSL_CA_CERTS
    
    logger.info("=" * 80)
    
    # Run with uvicorn
    uvicorn.run(
        app,
        host=SERVER_HOST,
        port=SERVER_PORT,
        log_level=LOG_LEVEL.lower(),
        **ssl_config
    )
