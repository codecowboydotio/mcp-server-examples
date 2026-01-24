#!/usr/bin/env python3
"""
Dockerfile Base Image Updater REST API

This service provides a REST API to automatically update Dockerfile base images
to their latest versions using AI analysis and commits the changes to GitHub.
"""

# curl -X POST "http://localhost:8000/update-dockerfile"   -H "Content-Type: application/json"   -d '{
#  "owner": "codecowboydotio",
#  "repo": "swapi-json-server",
#  "branch": "main",
#  "github_token": "XXX",
#  "dockerfile_path": "Dockerfile",
#  "commit_message": "Updated Dockerfile FROM via AI",
#  "dry_run": false
#}'


import asyncio
import base64
import json
import logging
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import uuid
import base64
import re
import requests
from typing import List

import requests
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, field_validator, Field
from langchain_anthropic import ChatAnthropic
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('dockerfile_updater_api.log')
    ]
)
logger = logging.getLogger(__name__)

from pydantic import BaseModel

class DockerfileRequest(BaseModel):
    owner: str
    repo: str
    branch: str = "main"
    github_token: str
    dockerfile_path: str = "Dockerfile"


class DockerfileInstruction(BaseModel):
    line_number: int
    instruction: str
    arguments: str
    raw_line: str


class DockerfileContent(BaseModel):
    owner: str
    repo: str
    branch: str
    path: str
    raw_content: str
    instructions: List[DockerfileInstruction]
    base_images: List[str]
    total_lines: int
    file_size: int
    sha: str

class JobStatus(str, Enum):
    """Job status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Config:
    """Configuration class for the application."""
    api_version: str = "2022-11-28"
    timeout: int = 30
    max_retries: int = 3
    ai_model: str = "claude-opus-4-1-20250805"


class DockerfileUpdateRequest(BaseModel):
    """Request model for Dockerfile update."""
    owner: str = Field(
        ...,
        description="GitHub repository owner (username or organization)",
        example="codecowboydotio"
    )
    repo: str = Field(
        ...,
        description="GitHub repository name",
        example="swapi-json-server"
    )
    branch: str = Field(
        default="main",
        description="Git branch to update",
        example="main"
    )
    github_token: str = Field(
        ...,
        description="GitHub personal access token with repo write permissions",
        example="ghp_xxxxxxxxxxxxxxxxxxxx"
    )
    dockerfile_path: str = Field(
        default="Dockerfile",
        description="Path to Dockerfile in the repository",
        example="Dockerfile"
    )
    commit_message: Optional[str] = Field(
        default="Updated Dockerfile FROM via AI",
        description="Commit message for the Dockerfile update",
        example="chore: update base image to latest version"
    )
    dry_run: bool = Field(
        default=False,
        description="If true, analyze changes but don't commit them",
        example=False
    )

    @field_validator('owner', 'repo')
    def validate_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Field cannot be empty')
        return v.strip()

    @field_validator('github_token')
    def validate_github_token(cls, v):
        if not v or len(v) < 10:
            raise ValueError('Invalid GitHub token')
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "owner": "codecowboydotio",
                "repo": "swapi-json-server",
                "branch": "main",
                "github_token": "ghp_xxxxxxxxxxxxxxxxxxxx",
                "dockerfile_path": "Dockerfile",
                "commit_message": "Updated Dockerfile FROM via AI",
                "dry_run": False
            }
        }


class DockerfileUpdateResponse(BaseModel):
    """Response model for Dockerfile update."""
    job_id: str = Field(
        ...,
        description="Unique identifier for the update job",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    status: JobStatus = Field(
        ...,
        description="Current status of the job",
        example="pending"
    )
    message: str = Field(
        ...,
        description="Human-readable status message",
        example="Job created and queued for processing"
    )
    timestamp: datetime = Field(
        ...,
        description="Timestamp when the response was generated",
        example="2024-01-15T10:30:00Z"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "pending",
                "message": "Job created and queued for processing",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        }


class JobStatusResponse(BaseModel):
    """Response model for job status."""
    job_id: str = Field(
        ...,
        description="Unique identifier for the job",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    status: JobStatus = Field(
        ...,
        description="Current status of the job",
        example="completed"
    )
    message: str = Field(
        ...,
        description="Human-readable status message",
        example="Successfully updated and committed Dockerfile"
    )
    timestamp: datetime = Field(
        ...,
        description="Timestamp of the last status update",
        example="2024-01-15T10:35:00Z"
    )
    owner: str = Field(
        ...,
        description="Repository owner",
        example="codecowboydotio"
    )
    repo: str = Field(
        ...,
        description="Repository name",
        example="swapi-json-server"
    )
    branch: str = Field(
        ...,
        description="Git branch",
        example="main"
    )
    dry_run: bool = Field(
        ...,
        description="Whether this was a dry run",
        example=False
    )
    dockerfile_path: str = Field(
        ...,
        description="Path to Dockerfile",
        example="Dockerfile"
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when job was created",
        example="2024-01-15T10:30:00Z"
    )
    updated_at: datetime = Field(
        ...,
        description="Timestamp when job was last updated",
        example="2024-01-15T10:35:00Z"
    )
    commit_sha: Optional[str] = Field(
        default=None,
        description="Git commit SHA (only for live updates)",
        example="abc123def456"
    )
    result: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Job result data (only available when completed)",
        example={
            "changed": True,
            "current_from": "FROM node:18",
            "updated_from": "FROM node:20",
            "commit_sha": "abc123def456",
            "file_url": "https://github.com/owner/repo/blob/main/Dockerfile"
        }
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message (only available when failed)",
        example="Failed to connect to GitHub API"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "completed",
                "message": "Successfully updated and committed Dockerfile",
                "timestamp": "2024-01-15T10:35:00Z",
                "owner": "codecowboydotio",
                "repo": "swapi-json-server",
                "branch": "main",
                "dry_run": False,
                "dockerfile_path": "Dockerfile",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:35:00Z",
                "commit_sha": "abc123def456",
                "result": {
                    "changed": True,
                    "current_from": "FROM node:18",
                    "updated_from": "FROM node:20",
                    "commit_sha": "abc123def456",
                    "file_url": "https://github.com/owner/repo/blob/main/Dockerfile"
                },
                "error": None
            }
        }


class HealthCheckResponse(BaseModel):
    """Response model for health check."""
    status: str = Field(
        ...,
        description="Health status of the service",
        example="healthy"
    )
    timestamp: datetime = Field(
        ...,
        description="Current server timestamp",
        example="2024-01-15T10:30:00Z"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        }


class DeleteJobResponse(BaseModel):
    """Response model for job deletion."""
    message: str = Field(
        ...,
        description="Confirmation message",
        example="Job deleted successfully"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Job deleted successfully"
            }
        }


@dataclass
class JobResult:
    """Job result data class."""
    job_id: str
    status: JobStatus
    message: str
    timestamp: datetime
    owner: str
    repo: str
    branch: str
    dry_run: bool
    dockerfile_path: str
    created_at: datetime
    updated_at: datetime
    commit_sha: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class DockerfileUpdaterError(Exception):
    """Custom exception for Dockerfile updater errors."""
    pass


class HTTPClient:
    """HTTP client with retry logic and proper error handling."""

    def __init__(self, timeout: int = 30, max_retries: int = 3):
        self.session = requests.Session()
        self.timeout = timeout

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "PUT"],
            backoff_factor=1
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url: str, **kwargs) -> requests.Response:
        """Make GET request with error handling."""
        try:
            kwargs.setdefault('timeout', self.timeout)
            response = self.session.get(url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"GET request failed for {url}: {e}")
            raise DockerfileUpdaterError(f"HTTP GET failed: {e}")

    def put(self, url: str, **kwargs) -> requests.Response:
        """Make PUT request with error handling."""
        try:
            kwargs.setdefault('timeout', self.timeout)
            response = self.session.put(url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"PUT request failed for {url}: {e}")
            raise DockerfileUpdaterError(f"HTTP PUT failed: {e}")


class GitHubAPI:
    """GitHub API client with proper error handling."""

    def __init__(self, token: str, owner: str, repo: str, config: Config, http_client: HTTPClient):
        self.token = token
        self.owner = owner
        self.repo = repo
        self.config = config
        self.http_client = http_client
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": config.api_version,
            "Content-Type": "application/json"
        }

    def get_repository_contents(self) -> List[Dict[str, Any]]:
        """Get repository contents."""
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/contents/"
        logger.info(f"Fetching repository contents from {url}")

        response = self.http_client.get(url, headers=self.headers)

        if response.status_code == 204:
            raise DockerfileUpdaterError("Repository is empty or deployment in progress")

        try:
            return response.json()
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            raise DockerfileUpdaterError("Invalid JSON response from GitHub API")

    def get_file_content(self, download_url: str) -> str:
        """Download file content from GitHub."""
        logger.info(f"Downloading file from {download_url}")
        response = self.http_client.get(download_url)
        return response.text

    def get_file_sha(self, file_path: str, branch: str) -> Optional[str]:
        """Get the SHA of an existing file."""
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/contents/{file_path}"
        params = {"ref": branch}

        try:
            response = self.http_client.get(url, headers=self.headers, params=params)
            return response.json()["sha"]
        except DockerfileUpdaterError:
            # File doesn't exist
            return None

    def commit_file(self, file_path: str, content: str, commit_message: str, branch: str) -> Dict[str, Any]:
        """Commit file to repository."""
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/contents/{file_path}"

        # Encode content to base64
        try:
            content_encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        except UnicodeEncodeError as e:
            raise DockerfileUpdaterError(f"Failed to encode file content: {e}")

        payload = {
            "message": commit_message,
            "content": content_encoded,
            "branch": branch
        }

        # Get existing file SHA if file exists
        existing_sha = self.get_file_sha(file_path, branch)
        if existing_sha:
            payload["sha"] = existing_sha
            logger.info(f"Updating existing file {file_path}")
        else:
            logger.info(f"Creating new file {file_path}")

        response = self.http_client.put(url, headers=self.headers, data=json.dumps(payload))
        return response.json()


class AIAnalyzer:
    """AI-powered Dockerfile analyzer."""

    def __init__(self, model_name: str = "claude-opus-4-1-20250805"):
        try:
            # Ensure Anthropic API key is available
            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise DockerfileUpdaterError("ANTHROPIC_API_KEY environment variable is required")

            self.model = ChatAnthropic(model=model_name)
            logger.info(f"Initialized AI model: {model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize AI model: {e}")
            raise DockerfileUpdaterError(f"AI model initialization failed: {e}")

    def find_dockerfile_url(self, repository_contents: List[Dict[str, Any]], dockerfile_path: str) -> str:
        """Find Dockerfile URL in repository contents using AI."""
        # First try to find the file directly by name
        for item in repository_contents:
            if item.get("name") == dockerfile_path and item.get("type") == "file":
                return item.get("download_url")

        # If not found directly, use AI to search
        dockerfile_schema = {
            "title": "dockerfile",
            "description": "Format of dockerfile links",
            "type": "object",
            "properties": {
                "textresponse": {
                    "type": "string",
                    "description": "The text response portion",
                },
                "fileurl": {
                    "type": "string",
                    "description": "The actual url of the file",
                },
            },
            "required": ["textresponse", "fileurl"],
        }

        structured_model = self.model.with_structured_output(dockerfile_schema)

        try:
            response = structured_model.invoke(
                f'Find dockerfile named "{dockerfile_path}" in array {repository_contents} return only value download_url'
            )
            logger.info("Successfully found Dockerfile URL using AI")
            return response["fileurl"]
        except Exception as e:
            logger.error(f"AI analysis failed for finding Dockerfile: {e}")
            raise DockerfileUpdaterError(f"Failed to find Dockerfile '{dockerfile_path}': {e}")

    def update_dockerfile_base_image(self, dockerfile_content: str) -> str:
        """Update Dockerfile base image using AI."""
        dockerfile_schema = {
            "title": "dockerfile",
            "description": "the dockerfile",
            "type": "object",
            "properties": {
                "textresponse": {
                    "type": "string",
                    "description": "The text response portion",
                },
                "dockerfile": {
                    "type": "string",
                    "description": "the dockerfile",
                },
            },
            "required": ["textresponse", "dockerfile"],
        }

        structured_model = self.model.with_structured_output(dockerfile_schema)

        try:
            prompt = (
                f'Update the FROM command to be the latest baseimage version for {dockerfile_content}, '
                'return the updated dockerfile. Make no changes if the baseimage is already at the latest version'
            )
            response = structured_model.invoke(prompt)
            logger.info("Successfully analyzed Dockerfile for base image updates")
            return response["dockerfile"]
        except Exception as e:
            logger.error(f"AI analysis failed for updating Dockerfile: {e}")
            raise DockerfileUpdaterError(f"Failed to update Dockerfile: {e}")


class JobManager:
    """Manages background jobs."""

    def __init__(self):
        self.jobs: Dict[str, JobResult] = {}

    def create_job(self, job_id: str, owner: str, repo: str, branch: str, dry_run: bool, dockerfile_path: str = "Dockerfile") -> None:
        """Create a new job."""
        now = datetime.now()
        self.jobs[job_id] = JobResult(
            job_id=job_id,
            status=JobStatus.PENDING,
            message="Job created",
            timestamp=now,
            owner=owner,
            repo=repo,
            branch=branch,
            dry_run=dry_run,
            dockerfile_path=dockerfile_path,
            created_at=now,
            updated_at=now
        )

    def update_job(self, job_id: str, status: JobStatus, message: str,
                   result: Optional[Dict[str, Any]] = None, error: Optional[str] = None,
                   commit_sha: Optional[str] = None) -> None:
        """Update job status."""
        if job_id in self.jobs:
            self.jobs[job_id].status = status
            self.jobs[job_id].message = message
            self.jobs[job_id].timestamp = datetime.now()
            self.jobs[job_id].updated_at = datetime.now()
            self.jobs[job_id].result = result
            self.jobs[job_id].error = error
            if commit_sha:
                self.jobs[job_id].commit_sha = commit_sha

    def get_job(self, job_id: str) -> Optional[JobResult]:
        """Get job by ID."""
        return self.jobs.get(job_id)

    def list_jobs(self) -> List[JobResult]:
        """List all jobs."""
        return list(self.jobs.values())


class DockerfileUpdaterService:
    """Main service class."""

    def __init__(self, config: Config):
        self.config = config
        self.http_client = HTTPClient(config.timeout, config.max_retries)
        self.ai_analyzer = AIAnalyzer(config.ai_model)
        self.job_manager = JobManager()

    async def update_dockerfile(self, job_id: str, request: DockerfileUpdateRequest) -> None:
        """Update Dockerfile in background."""
        try:
            self.job_manager.update_job(job_id, JobStatus.RUNNING, "Starting Dockerfile update process")

            # Initialize GitHub API client
            github_api = GitHubAPI(
                request.github_token,
                request.owner,
                request.repo,
                self.config,
                self.http_client
            )

            # Get repository contents
            contents = github_api.get_repository_contents()
            self.job_manager.update_job(job_id, JobStatus.RUNNING, "Retrieved repository contents")

            # Find Dockerfile URL
            dockerfile_url = self.ai_analyzer.find_dockerfile_url(contents, request.dockerfile_path)
            self.job_manager.update_job(job_id, JobStatus.RUNNING, f"Found Dockerfile at: {dockerfile_url}")

            # Download current Dockerfile
            current_dockerfile = github_api.get_file_content(dockerfile_url)
            current_first_line = current_dockerfile.split('\n', 1)[0] if current_dockerfile else ""

            # Update Dockerfile using AI
            updated_dockerfile = self.ai_analyzer.update_dockerfile_base_image(current_dockerfile)
            updated_first_line = updated_dockerfile.split('\n', 1)[0] if updated_dockerfile else ""

            # Check if changes are needed
            if current_first_line == updated_first_line:
                self.job_manager.update_job(
                    job_id,
                    JobStatus.COMPLETED,
                    "No changes needed - Dockerfile is already up to date",
                    result={
                        "changed": False,
                        "current_from": current_first_line,
                        "updated_from": updated_first_line
                    }
                )
                return

            result_data = {
                "changed": True,
                "current_from": current_first_line,
                "updated_from": updated_first_line,
                "dry_run": request.dry_run
            }

            # Commit updated Dockerfile (unless dry run)
            if not request.dry_run:
                commit_result = github_api.commit_file(
                    file_path=request.dockerfile_path,
                    content=updated_dockerfile,
                    commit_message=request.commit_message,
                    branch=request.branch
                )

                commit_sha = commit_result['commit']['sha']
                result_data.update({
                    "commit_sha": commit_sha,
                    "file_url": commit_result['content']['html_url']
                })

                self.job_manager.update_job(
                    job_id,
                    JobStatus.COMPLETED,
                    "Successfully updated and committed Dockerfile",
                    result=result_data,
                    commit_sha=commit_sha
                )
            else:
                self.job_manager.update_job(
                    job_id,
                    JobStatus.COMPLETED,
                    "Dry run completed - changes detected but not committed",
                    result=result_data
                )

        except Exception as e:
            error_message = str(e)
            logger.error(f"Job {job_id} failed: {error_message}")
            self.job_manager.update_job(
                job_id,
                JobStatus.FAILED,
                "Job failed with error",
                error=error_message
            )


# Initialize FastAPI app with enhanced OpenAPI configuration
app = FastAPI(
    title="Dockerfile Base Image Updater API",
    description="""
## Overview

The Dockerfile Base Image Updater API provides an automated solution for keeping your Dockerfile base images
up-to-date using AI-powered analysis. This service integrates with GitHub to analyze, update, and commit
changes to Dockerfiles in your repositories.

## Features

* 🤖 **AI-Powered Analysis**: Uses Claude AI to intelligently identify and update base images
* 🔄 **Automated Updates**: Automatically detects outdated base images and suggests latest versions
* 🔐 **GitHub Integration**: Seamlessly commits changes to your GitHub repositories
* 📊 **Job Management**: Track update jobs with detailed status information
* 🧪 **Dry Run Mode**: Preview changes before committing them
* 🔍 **Smart Detection**: Intelligently locates Dockerfiles in your repository structure

## Authentication

API endpoints support optional Bearer token authentication. Include your token in the Authorization header:

```
Authorization: Bearer <your-token>
```

## Prerequisites

Before using this API, ensure you have:

1. A GitHub Personal Access Token with `repo` write permissions
2. An Anthropic API key (configured on the server)
3. A repository containing a Dockerfile

## Workflow

1. **Submit Update Request**: POST to `/update-dockerfile` with repository details
2. **Receive Job ID**: Get a unique job identifier to track progress
3. **Poll Job Status**: GET `/jobs/{job_id}` to check completion status
4. **Review Results**: View changes, commit information, and any errors

## Rate Limits

The API implements automatic retry logic with exponential backoff for GitHub API requests.

## Support

For issues or questions, please refer to the project documentation or contact the development team.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "Health",
            "description": "Health check and service status endpoints"
        },
        {
            "name": "Dockerfile Operations",
            "description": "Operations for updating Dockerfile base images"
        },
        {
            "name": "Job Management",
            "description": "Manage and track update jobs"
        }
    ],
    contact={
        "name": "API Support",
        "email": "support@example.com",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
config = Config()
service = DockerfileUpdaterService(config)

# Security
security = HTTPBearer(auto_error=False)

def parse_dockerfile(content: str) -> tuple[List[DockerfileInstruction], List[str]]:
    """
    Parse Dockerfile content into structured instructions
    Returns: (instructions, base_images)
    """
    instructions = []
    base_images = []
    lines = content.split('\n')

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            continue

        # Parse instruction
        match = re.match(r'^([A-Z]+)\s+(.+)$', stripped)
        if match:
            instruction = match.group(1)
            arguments = match.group(2)

            instructions.append(DockerfileInstruction(
                line_number=line_num,
                instruction=instruction,
                arguments=arguments,
                raw_line=line
            ))

            # Extract base images from FROM instructions
            if instruction == 'FROM':
                image = arguments.split(' AS ')[0].strip()
                base_images.append(image)

    return instructions, base_images

async def get_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate API key (optional)."""
    # You can implement API key validation here if needed
    return credentials

@app.get("/dockerfile", response_model=DockerfileContent)
async def get_dockerfile_get(
    owner: str,
    repo: str,
    branch: str = "main",
    github_token: str = None,
    dockerfile_path: str = "Dockerfile"
):
    """GET version - parameters in URL"""
    return await get_dockerfile_post(DockerfileRequest(
        owner=owner,
        repo=repo,
        branch=branch,
        github_token=github_token or "",
        dockerfile_path=dockerfile_path
    ))


@app.post("/dockerfile", response_model=DockerfileContent)
async def get_dockerfile_post(request: DockerfileRequest):
    """
    Fetch and parse a Dockerfile from a GitHub repository
    """
    url = f"https://api.github.com/repos/{request.owner}/{request.repo}/contents/{request.dockerfile_path}"
    params = {"ref": request.branch}

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Dockerfile-Updater-Service"
    }

    if request.github_token:
        headers["Authorization"] = f"token {request.github_token}"

    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)

        if response.status_code == 404:
            raise HTTPException(
                status_code=404,
                detail=f"Dockerfile not found at {request.owner}/{request.repo}/{request.dockerfile_path}"
            )
        elif response.status_code == 401:
            raise HTTPException(status_code=401, detail="Invalid GitHub token")
        elif response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"GitHub API error: {response.text}"
            )

        file_data = response.json()

        if file_data.get('encoding') == 'base64':
            content = base64.b64decode(file_data['content']).decode('utf-8')
        else:
            raise HTTPException(status_code=500, detail="Unexpected encoding")

        instructions, base_images = parse_dockerfile(content)

        return DockerfileContent(
            owner=request.owner,
            repo=request.repo,
            branch=request.branch,
            path=request.dockerfile_path,
            raw_content=content,
            instructions=instructions,
            base_images=base_images,
            total_lines=len(content.split('\n')),
            file_size=len(content),
            sha=file_data.get('sha', '')
        )

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"GitHub request failed: {str(e)}")


@app.get(
    "/health",
    response_model=HealthCheckResponse,
    tags=["Health"],
    summary="Health Check",
    description="Check if the API service is running and healthy",
    responses={
        200: {
            "description": "Service is healthy",
            "content": {
                "application/json": {
                    "example": {
                        "status": "healthy",
                        "timestamp": "2024-01-15T10:30:00Z"
                    }
                }
            }
        }
    }
)
async def health_check():
    """
    Health check endpoint to verify the service is running.

    Returns:
        HealthCheckResponse: Status and timestamp
    """
    return HealthCheckResponse(status="healthy", timestamp=datetime.now())


@app.post(
    "/update-dockerfile",
    response_model=DockerfileUpdateResponse,
    tags=["Dockerfile Operations"],
    summary="Update Dockerfile Base Image",
    description="""
    Submit a request to update the base image in a Dockerfile using AI analysis.

    This endpoint creates a background job that will:
    1. Fetch the repository contents from GitHub
    2. Locate the specified Dockerfile
    3. Analyze the current base image using AI
    4. Determine if an update is available
    5. Optionally commit the updated Dockerfile (if not in dry-run mode)

    The operation is asynchronous - use the returned job_id to poll for completion status.
    """,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {
            "description": "Update job created successfully",
            "content": {
                "application/json": {
                    "example": {
                        "job_id": "550e8400-e29b-41d4-a716-446655440000",
                        "status": "pending",
                        "message": "Job created and queued for processing",
                        "timestamp": "2024-01-15T10:30:00Z"
                    }
                }
            }
        },
        400: {
            "description": "Invalid request parameters",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid GitHub token"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to create update job"
                    }
                }
            }
        }
    }
)
async def update_dockerfile(
    request: DockerfileUpdateRequest,
    background_tasks: BackgroundTasks,
    credentials: HTTPAuthorizationCredentials = Depends(get_api_key)
):
    """
    Update Dockerfile base image.

    Args:
        request: Dockerfile update request parameters
        background_tasks: FastAPI background tasks
        credentials: Optional API authentication credentials

    Returns:
        DockerfileUpdateResponse: Job ID and initial status

    Raises:
        HTTPException: If job creation fails
    """
    try:
        # Generate job ID
        job_id = str(uuid.uuid4())

        # Create job with all necessary fields
        service.job_manager.create_job(
            job_id,
            request.owner,
            request.repo,
            request.branch,
            request.dry_run,
            request.dockerfile_path
        )

        # Start background task
        background_tasks.add_task(service.update_dockerfile, job_id, request)

        return DockerfileUpdateResponse(
            job_id=job_id,
            status=JobStatus.PENDING,
            message="Job created and queued for processing",
            timestamp=datetime.now()
        )

    except Exception as e:
        logger.error(f"Failed to create update job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    tags=["Job Management"],
    summary="Get Job Status",
    description="""
    Retrieve the current status and results of a specific job.

    Use this endpoint to poll for job completion after submitting an update request.
    The response will include detailed information about the job's progress and any results or errors.
    """,
    responses={
        200: {
            "description": "Job status retrieved successfully",
            "content": {
                "application/json": {
                    "examples": {
                        "completed": {
                            "summary": "Completed job with changes",
                            "value": {
                                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                                "status": "completed",
                                "message": "Successfully updated and committed Dockerfile",
                                "timestamp": "2024-01-15T10:35:00Z",
                                "result": {
                                    "changed": True,
                                    "current_from": "FROM node:18",
                                    "updated_from": "FROM node:20",
                                    "commit_sha": "abc123def456",
                                    "file_url": "https://github.com/owner/repo/blob/main/Dockerfile"
                                },
                                "error": None
                            }
                        },
                        "running": {
                            "summary": "Job in progress",
                            "value": {
                                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                                "status": "running",
                                "message": "Analyzing Dockerfile for updates",
                                "timestamp": "2024-01-15T10:32:00Z",
                                "result": None,
                                "error": None
                            }
                        },
                        "failed": {
                            "summary": "Failed job",
                            "value": {
                                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                                "status": "failed",
                                "message": "Job failed with error",
                                "timestamp": "2024-01-15T10:33:00Z",
                                "result": None,
                                "error": "Failed to connect to GitHub API"
                            }
                        }
                    }
                }
            }
        },
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Job not found"
                    }
                }
            }
        }
    }
)
async def get_job_status(
    job_id: str = Path(
        ...,
        description="Unique job identifier",
        examples="550e8400-e29b-41d4-a716-446655440000"
    )
):
    """
    Get job status by ID.

    Args:
        job_id: Unique identifier for the job

    Returns:
        JobStatusResponse: Current job status and results

    Raises:
        HTTPException: If job is not found
    """
    job = service.job_manager.get_job(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobStatusResponse(**asdict(job))


@app.get(
    "/jobs",
    response_model=List[JobStatusResponse],
    tags=["Job Management"],
    summary="List All Jobs",
    description="""
    Retrieve a list of all jobs in the system.

    This endpoint returns all jobs regardless of status, including pending, running, completed, and failed jobs.
    Useful for monitoring and debugging purposes.
    """,
    responses={
        200: {
            "description": "List of all jobs",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "job_id": "550e8400-e29b-41d4-a716-446655440000",
                            "status": "completed",
                            "message": "Successfully updated and committed Dockerfile",
                            "timestamp": "2024-01-15T10:35:00Z",
                            "result": {
                                "changed": True,
                                "current_from": "FROM node:18",
                                "updated_from": "FROM node:20"
                            },
                            "error": None
                        },
                        {
                            "job_id": "660e8400-e29b-41d4-a716-446655440001",
                            "status": "running",
                            "message": "Analyzing Dockerfile",
                            "timestamp": "2024-01-15T10:36:00Z",
                            "result": None,
                            "error": None
                        }
                    ]
                }
            }
        }
    }
)
async def list_jobs():
    """
    List all jobs.

    Returns:
        List[JobStatusResponse]: List of all jobs in the system
    """
    jobs = service.job_manager.list_jobs()
    return [JobStatusResponse(**asdict(job)) for job in jobs]


@app.delete(
    "/jobs/{job_id}",
    response_model=DeleteJobResponse,
    tags=["Job Management"],
    summary="Delete Job",
    description="""
    Delete a specific job from the system.

    This removes the job and all associated data from memory. Note that this does not
    reverse any changes that were committed to GitHub.
    """,
    responses={
        200: {
            "description": "Job deleted successfully",
            "content": {
                "application/json": {
                    "example": {
                        "message": "Job deleted successfully"
                    }
                }
            }
        },
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Job not found"
                    }
                }
            }
        }
    }
)
async def delete_job(
    job_id: str = Path(
        ...,
        description="Unique job identifier to delete",
        examples="550e8400-e29b-41d4-a716-446655440000"
    )
):
    """
    Delete job by ID.

    Args:
        job_id: Unique identifier for the job to delete

    Returns:
        DeleteJobResponse: Confirmation message

    Raises:
        HTTPException: If job is not found
    """
    if job_id not in service.job_manager.jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    del service.job_manager.jobs[job_id]
    return DeleteJobResponse(message="Job deleted successfully")


# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Add security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Optional Bearer token authentication"
        }
    }

    # Add servers
    openapi_schema["servers"] = [
        {
            "url": "http://localhost:8000",
            "description": "Local development server"
        },
        {
            "url": "https://api.example.com",
            "description": "Production server"
        }
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    import uvicorn

    # Ensure required environment variables
    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.error("ANTHROPIC_API_KEY environment variable is required")
        sys.exit(1)

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
