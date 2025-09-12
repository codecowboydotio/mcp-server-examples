#!/usr/bin/python

import getpass
import os
import requests
import json
from langchain.chat_models import init_chat_model
import base64
from typing import Optional


if not os.environ.get("GIT_PAT_AI"):
  os.environ["GIT_PAT_AI"] = getpass.getpass("Enter API key for Github: ")
else:
  GIT_TOKEN=os.environ["GIT_PAT_AI"]

if not os.environ.get("ANTHROPIC_API_KEY"):
  os.environ["ANTHROPIC_API_KEY"] = getpass.getpass("Enter API key for Anthropic: ")


GITHUB_TOKEN = GIT_TOKEN # Create at https://github.com/settings/tokens
OWNER = "codecowboydotio"  # Your GitHub username or organization
REPO = "swapi-json-server"  # Repository n

class GitHubCommitter:
    def __init__(self, token: str, owner: str, repo: str):
        """
        Initialize GitHub committer.
        
        Args:
            token: GitHub personal access token
            owner: Repository owner (username or organization)
            repo: Repository name
        """
        self.token = token
        self.owner = owner
        self.repo = repo
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
    
    def get_file_sha(self, file_path: str, branch: str = "main") -> Optional[str]:
        """Get the SHA of an existing file (needed for updates)."""
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/contents/{file_path}"
        params = {"ref": branch}
        
        response = requests.get(url, headers=self.headers, params=params)
        
        if response.status_code == 200:
            return response.json()["sha"]
        elif response.status_code == 404:
            return None  # File doesn't exist
        else:
            response.raise_for_status()
    
    def commit_file(self, file_path: str, content: str, commit_message: str, 
                   branch: str = "main", update_existing: bool = True) -> dict:
        """
        Create or update a file and commit it.
        
        Args:
            file_path: Path to the file in the repository
            content: File content as string
            commit_message: Commit message
            branch: Branch to commit to
            update_existing: Whether to update if file exists
            
        Returns:
            API response as dictionary
        """
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/contents/{file_path}"
        
        # Encode content to base64
        content_encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        # Prepare the payload
        payload = {
            "message": commit_message,
            "content": content_encoded,
            "branch": branch
        }
        
        # Check if file exists and get its SHA if it does
        if update_existing:
            existing_sha = self.get_file_sha(file_path, branch)
            if existing_sha:
                payload["sha"] = existing_sha
        
        # Make the request
        response = requests.put(url, headers=self.headers, data=json.dumps(payload))
        
        if response.status_code in [200, 201]:
            return response.json()
        else:
            response.raise_for_status()



url='https://api.github.com/repos/codecowboydotio/swapi-json-server/contents/'

headers = {
  "Accept": "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Authorization": f'Bearer {GIT_TOKEN}'
}

query_answer = requests.get(url, headers=headers)
query_response_code = query_answer.status_code
if query_response_code  == 204:
  print("Please check github actions for the status of the deployment")
else:
#  print(query_answer.text)
  print("Contacting git....")
  print("Got response...")


model = init_chat_model("claude-opus-4-1-20250805", model_provider="anthropic")
#model = init_chat_model("claude-3-5-sonnet-latest", model_provider="anthropic")

dockerfiles_json_schema = {
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

structured_model = model.with_structured_output(dockerfiles_json_schema)
print("Initializing model...")
try:
  response = structured_model.invoke(f'find dockerfiles in array {query_answer.text} return only value download_url')
except Exception as e:
  print(f"LLM error: {e}")
  exit(1)
print("Found dockerfile...")
#print(response)

print("Pulling dockerfile from git....")
dockerfile = requests.get(response["fileurl"])
docker_response = dockerfile.text
first_line = docker_response.split('\n', 1)[0]
print("Original: " + first_line)

dockerfile_json_schema = {
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
print("Sending entire dockerfile to LLM to determine latest baseimage...")
dockerfile_structured_model = model.with_structured_output(dockerfile_json_schema)
#response = dockerfile_structured_model.invoke(f'Update the FROM command to be the latest baseimage version for {dockerfile.text}, return the updated dockerfile')
response = dockerfile_structured_model.invoke(f'Update the FROM command to be the latest baseimage version for {dockerfile.text}, return the updated dockerfile make no changes if the baseimage is already at the latest version')
#print("===========")
#print(response["dockerfile"])


llm_docker_response = response["dockerfile"]
llm_first_line = llm_docker_response.split('\n', 1)[0]
print("Replacement: " + llm_first_line)

if (llm_first_line == first_line):
  print("Original and replacement are the same..... doing nothing")
  exit(1)
else:
  # File details
  file_path = "Dockerfile"
  file_content = response["dockerfile"]
  #file_content = """Hello, World!
  #This is a test file created via GitHub API.
  #Current timestamp: """ + str(requests.get("http://worldtimeapi.org/api/timezone/Australia/Melbourne").json().get("datetime", "unknown"))
  
  commit_message = "Updated Dockerfile FROM via AI"
  branch = "main"  # or "master" depending on your default branch
  
  try:
      # Create committer instance
      committer = GitHubCommitter(GITHUB_TOKEN, OWNER, REPO)
  
      # Commit the file
      print(f"Committing file '{file_path}' to {OWNER}/{REPO}...")
      result = committer.commit_file(
          file_path=file_path,
          content=file_content,
          commit_message=commit_message,
          branch=branch
      )
  
      print("✅ Success!")
      print(f"Commit SHA: {result['commit']['sha']}")
      print(f"File URL: {result['content']['html_url']}")
  except requests.exceptions.HTTPError as e:
      print(f"❌ HTTP Error: {e}")
      print(f"Response: {e.response.text}")
  except Exception as e:
      print(f"❌ Error: {e}")
