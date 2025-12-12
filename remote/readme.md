# SWAPI MCP Server

A remote Model Context Protocol (MCP) server that provides access to Star Wars API (SWAPI) data. This server runs over HTTPS with SSE (Server-Sent Events) transport and includes authentication, CORS support, and comprehensive logging.

## Features

- 🔒 **HTTPS/TLS Support** - Secure communication with SSL/TLS encryption
- 🔑 **API Key Authentication** - Optional API key-based authentication
- 🌐 **CORS Support** - Configurable cross-origin resource sharing
- 📝 **Comprehensive Logging** - Rotating log files with configurable levels
- 🚀 **SSE Transport** - Server-Sent Events for real-time communication
- 🛠️ **Two Tools**:
  - `get_swapi_character` - Get detailed character information by ID
  - `get_all_swapi_people` - Get all people from SWAPI

## Prerequisites

- Python 3.11 or higher
- Access to a SWAPI JSON server (e.g., http://10.1.1.150:3000)
- SSL certificates (for HTTPS mode)

## Installation

1. **Clone the repository:**
```bash
git clone <your-repo-url>
cd swapi-mcp-server
```

2. **Create a virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

**requirements.txt:**
```txt
mcp
fastmcp
httpx
uvicorn
python-dotenv
starlette
```

## SSL/TLS Certificate Generation

### Option 1: Self-Signed Certificates (Development/Testing)

#### Basic Self-Signed Certificate
```bash
# Generate a self-signed certificate valid for 365 days
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

#### Self-Signed Certificate with Subject Alternative Names (SAN)

For multiple domains or IP addresses:
```bash
# Create a configuration file
cat > openssl.cnf << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = State
L = City
O = Organization
CN = yourdomain.com

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = yourdomain.com
DNS.2 = *.yourdomain.com
DNS.3 = localhost
IP.1 = 10.1.1.150
IP.2 = 127.0.0.1
EOF

# Generate certificate with SAN
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -config openssl.cnf -extensions req_ext
```

#### Verify Your Certificate
```bash
# Check certificate details
openssl x509 -in cert.pem -text -noout

# Verify certificate and key match
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
```

### Option 2: Let's Encrypt (Production)

For production environments with a public domain:

#### Using Certbot (Standalone Mode)
```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot

# Stop any services running on port 80/443
sudo systemctl stop nginx  # or apache2

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Certificates will be created at:
# /etc/letsencrypt/live/yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

#### Using Certbot with Webroot

If you have a web server running:
```bash
sudo certbot certonly --webroot -w /var/www/html -d yourdomain.com
```

#### Auto-Renewal Setup
```bash
# Test renewal
sudo certbot renew --dry-run

# Setup automatic renewal (already configured by default)
sudo systemctl status certbot.timer
```

#### Set Permissions for Non-Root Access
```bash
# Create a group for certificate access
sudo groupadd certusers
sudo usermod -a -G certusers $USER

# Set permissions
sudo chgrp -R certusers /etc/letsencrypt/live
sudo chgrp -R certusers /etc/letsencrypt/archive
sudo chmod -R g+rx /etc/letsencrypt/live
sudo chmod -R g+rx /etc/letsencrypt/archive
```

### Option 3: Using a Certificate Authority (CA)

For organizational certificates:

1. **Generate a Certificate Signing Request (CSR):**
```bash
# Generate private key
openssl genrsa -out key.pem 4096

# Generate CSR
openssl req -new -key key.pem -out request.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=yourdomain.com"
```

2. **Submit the CSR to your CA** (e.g., DigiCert, GlobalSign, your organization's CA)

3. **Download the signed certificate** and any intermediate certificates

4. **Create full chain:**
```bash
# Combine your certificate with intermediate certificates
cat your_certificate.crt intermediate.crt > cert.pem
```

### Testing SSL Certificates
```bash
# Test SSL connection
openssl s_client -connect localhost:8443 -servername localhost

# Test with curl (accepting self-signed)
curl -k https://localhost:8443/

# Test certificate expiration
openssl x509 -in cert.pem -noout -enddate
```

## Configuration

Create a `.env` file in the project root:
```bash
# API Configuration
SWAPI_API_BASE=http://10.1.1.150:3000
USER_AGENT=swapi-app/1.0

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8443

# Security
MCP_API_KEY=your-secret-api-key-here

# SSL/TLS Configuration
USE_SSL=true
SSL_CERTFILE=cert.pem
SSL_KEYFILE=key.pem
# SSL_CA_CERTS=/path/to/ca-bundle.pem  # Optional

# CORS Configuration (comma-separated origins)
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Logging Configuration
LOG_FILE=/var/log/swapi-mcp/swapi-mcp.log
LOG_LEVEL=INFO
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=5
LOG_TO_CONSOLE=true
LOG_TO_FILE=true
```

### Configuration Options

#### Server Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `SWAPI_API_BASE` | Base URL for SWAPI JSON server | `http://10.1.1.150:3000` |
| `USER_AGENT` | User agent for API requests | `swapi-app/1.0` |
| `SERVER_HOST` | Host to bind the server | `0.0.0.0` |
| `SERVER_PORT` | Port to listen on | `8443` |

#### Security Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_API_KEY` | API key for authentication (optional) | None |
| `USE_SSL` | Enable/disable SSL | `true` |
| `SSL_CERTFILE` | Path to SSL certificate | `cert.pem` |
| `SSL_KEYFILE` | Path to SSL private key | `key.pem` |
| `SSL_CA_CERTS` | Path to CA bundle (optional) | None |

#### CORS Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `CORS_ORIGINS` | Comma-separated allowed origins | `*` |

#### Logging Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_FILE` | Path to log file | `swapi-mcp.log` |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `INFO` |
| `LOG_MAX_BYTES` | Max log file size before rotation (bytes) | `10485760` (10MB) |
| `LOG_BACKUP_COUNT` | Number of backup log files | `5` |
| `LOG_TO_CONSOLE` | Enable console logging | `true` |
| `LOG_TO_FILE` | Enable file logging | `true` |

## Running the Server

### Development Mode (HTTP, no auth)
```bash
# Create .env for development
cat > .env << EOF
USE_SSL=false
MCP_API_KEY=
LOG_LEVEL=DEBUG
LOG_TO_CONSOLE=true
LOG_TO_FILE=false
EOF

# Run the server
python swapi-remote.py
```

### Production Mode (HTTPS with auth)
```bash
# Ensure certificates exist
ls -l cert.pem key.pem

# Run the server
python swapi-remote.py
```

### Using systemd (Production Deployment)

1. **Create systemd service file:**
```bash
sudo nano /etc/systemd/system/swapi-mcp.service
```
```ini
[Unit]
Description=SWAPI MCP Server
After=network.target

[Service]
Type=simple
User=youruser
Group=yourgroup
WorkingDirectory=/path/to/swapi-mcp-server
Environment="PATH=/path/to/swapi-mcp-server/venv/bin"
EnvironmentFile=/path/to/swapi-mcp-server/.env
ExecStart=/path/to/swapi-mcp-server/venv/bin/python swapi-remote.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/swapi-mcp

[Install]
WantedBy=multi-user.target
```

2. **Enable and start service:**
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable swapi-mcp

# Start service
sudo systemctl start swapi-mcp

# Check status
sudo systemctl status swapi-mcp

# View logs
sudo journalctl -u swapi-mcp -f
```

### Using Docker

**Dockerfile:**
```dockerfile
FROM python:3.13-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY swapi-remote.py .
COPY cert.pem key.pem ./

# Create log directory
RUN mkdir -p /var/log/swapi-mcp

# Expose port
EXPOSE 8443

# Run the server
CMD ["python", "swapi-remote.py"]
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  swapi-mcp:
    build: .
    ports:
      - "8443:8443"
    environment:
      - SWAPI_API_BASE=http://10.1.1.150:3000
      - SERVER_HOST=0.0.0.0
      - SERVER_PORT=8443
      - USE_SSL=true
      - SSL_CERTFILE=/app/cert.pem
      - SSL_KEYFILE=/app/key.pem
      - MCP_API_KEY=${MCP_API_KEY}
      - LOG_FILE=/var/log/swapi-mcp/swapi-mcp.log
      - LOG_LEVEL=INFO
    volumes:
      - ./logs:/var/log/swapi-mcp
      - ./cert.pem:/app/cert.pem:ro
      - ./key.pem:/app/key.pem:ro
    restart: unless-stopped
```

**Build and run:**
```bash
# Build image
docker-compose build

# Run container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop container
docker-compose down
```

## Client Configuration

### Claude Desktop

Add to your Claude Desktop configuration:

**For macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

**For Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
```json
{
  "mcpServers": {
    "swapi": {
      "url": "https://your-server-ip:8443/sse",
      "headers": {
        "X-API-Key": "your-secret-api-key-here"
      }
    }
  }
}
```

### Self-Signed Certificates

If using self-signed certificates in development:
```json
{
  "mcpServers": {
    "swapi": {
      "url": "https://localhost:8443/sse",
      "headers": {
        "X-API-Key": "your-secret-api-key-here"
      },
      "verifySSL": false
    }
  }
}
```

⚠️ **Warning:** Only use `verifySSL: false` in development environments.

## Available Tools

### get_swapi_character

Get detailed information about a Star Wars character by ID.

**Parameters:**
- `id` (string, required): Character ID (numeric string)

**Example:**
```
Get information about character 1
```

**Response:**
```
Name: Luke Skywalker
Gender: male
Hair Colour: blond
Homeworld: Tatooine
```

### get_all_swapi_people

Get a list of all people from SWAPI.

**Parameters:** None

**Example:**
```
Get all people from SWAPI
```

**Response:** JSON array of all characters

## Logging

The server includes comprehensive logging with rotation:

- **Log Levels:** DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Log Rotation:** Automatic rotation when file size exceeds configured maximum
- **Backup Files:** Configurable number of backup log files
- **Dual Output:** Can log to both console and file simultaneously

### Log File Locations
```bash
# View current logs
tail -f /var/log/swapi-mcp/swapi-mcp.log

# View rotated logs
ls -lh /var/log/swapi-mcp/

# Search logs
grep "ERROR" /var/log/swapi-mcp/swapi-mcp.log
```

### Troubleshooting Logging Issues
```bash
# Check log directory permissions
ls -ld /var/log/swapi-mcp

# Create log directory if missing
sudo mkdir -p /var/log/swapi-mcp
sudo chown youruser:yourgroup /var/log/swapi-mcp

# Test with console logging only
LOG_TO_FILE=false LOG_TO_CONSOLE=true python swapi-remote.py
```

## Troubleshooting

### SSL Certificate Errors
```bash
# Verify certificate
openssl x509 -in cert.pem -text -noout

# Check certificate and key match
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
# These should output the same hash

# Test SSL connection
openssl s_client -connect localhost:8443
```

### Connection Issues
```bash
# Check if port is open
netstat -tuln | grep 8443

# Test with curl
curl -k https://localhost:8443/

# Check firewall
sudo ufw status
sudo ufw allow 8443/tcp
```

### Permission Issues
```bash
# Fix certificate permissions
chmod 600 key.pem
chmod 644 cert.pem

# Fix log directory permissions
sudo chown -R youruser:yourgroup /var/log/swapi-mcp
sudo chmod 755 /var/log/swapi-mcp
```

### API Connection Issues
```bash
# Test SWAPI backend
curl http://10.1.1.150:3000/people/1

# Check network connectivity
ping 10.1.1.150
```

## Security Best Practices

1. **Always use HTTPS in production** - Set `USE_SSL=true`
2. **Use strong API keys** - Generate with: `openssl rand -hex 32`
3. **Restrict CORS origins** - Don't use `*` in production
4. **Keep certificates updated** - Monitor expiration dates
5. **Use proper file permissions** - Certificate files should be readable only by the service user
6. **Enable logging** - Monitor for security issues
7. **Run as non-root user** - Use systemd service with dedicated user
8. **Keep dependencies updated** - Regularly update Python packages

## Development

### Running Tests
```bash
# Install dev dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### Code Quality
```bash
# Install linters
pip install black flake8 mypy

# Format code
black swapi-remote.py

# Lint code
flake8 swapi-remote.py

# Type checking
mypy swapi-remote.py
```

## License

[Your License Here]

## Contributing

[Your Contributing Guidelines Here]

## Support

For issues and questions:
- GitHub Issues: [Your Issues URL]
- Email: [Your Email]
- Documentation: [Your Docs URL]
