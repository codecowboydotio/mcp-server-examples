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

import requests
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator, field_validator
from langchain.chat_models import init_chat_model
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
    owner: str
    repo: str
    branch: str = "main"
    github_token: str
    dockerfile_path: str = "Dockerfile"
    commit_message: Optional[str] = "Updated Dockerfile FROM via AI"
    dry_run: bool = False
    
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


class DockerfileUpdateResponse(BaseModel):
    """Response model for Dockerfile update."""
    job_id: str
    status: JobStatus
    message: str
    timestamp: datetime


class JobStatusResponse(BaseModel):
    """Response model for job status."""
    job_id: str
    status: JobStatus
    message: str
    timestamp: datetime
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class JobResult:
    """Job result data class."""
    job_id: str
    status: JobStatus
    message: str
    timestamp: datetime
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
            
            self.model = init_chat_model(model_name, model_provider="anthropic")
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
    
    def create_job(self, job_id: str) -> None:
        """Create a new job."""
        self.jobs[job_id] = JobResult(
            job_id=job_id,
            status=JobStatus.PENDING,
            message="Job created",
            timestamp=datetime.now()
        )
    
    def update_job(self, job_id: str, status: JobStatus, message: str, 
                   result: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> None:
        """Update job status."""
        if job_id in self.jobs:
            self.jobs[job_id].status = status
            self.jobs[job_id].message = message
            self.jobs[job_id].timestamp = datetime.now()
            self.jobs[job_id].result = result
            self.jobs[job_id].error = error
    
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
                
                result_data.update({
                    "commit_sha": commit_result['commit']['sha'],
                    "file_url": commit_result['content']['html_url']
                })
                
                self.job_manager.update_job(
                    job_id,
                    JobStatus.COMPLETED,
                    "Successfully updated and committed Dockerfile",
                    result=result_data
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


# Initialize FastAPI app
app = FastAPI(
    title="Dockerfile Updater API",
    description="REST API for updating Dockerfile base images using AI",
    version="1.0.0"
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


async def get_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate API key (optional)."""
    # You can implement API key validation here if needed
    return credentials


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now()}


@app.post("/update-dockerfile", response_model=DockerfileUpdateResponse)
async def update_dockerfile(
    request: DockerfileUpdateRequest,
    background_tasks: BackgroundTasks,
    credentials: HTTPAuthorizationCredentials = Depends(get_api_key)
):
    """Update Dockerfile base image."""
    try:
        # Generate job ID
        job_id = str(uuid.uuid4())
        
        # Create job
        service.job_manager.create_job(job_id)
        
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


@app.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    """Get job status by ID."""
    job = service.job_manager.get_job(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return JobStatusResponse(**asdict(job))


@app.get("/jobs", response_model=List[JobStatusResponse])
async def list_jobs():
    """List all jobs."""
    jobs = service.job_manager.list_jobs()
    return [JobStatusResponse(**asdict(job)) for job in jobs]


@app.delete("/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete job by ID."""
    if job_id not in service.job_manager.jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    del service.job_manager.jobs[job_id]
    return {"message": "Job deleted successfully"}


if __name__ == "__main__":
    import uvicorn
    
    # Ensure required environment variables
    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.error("ANTHROPIC_API_KEY environment variable is required")
        sys.exit(1)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
