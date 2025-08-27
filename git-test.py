#!/usr/bin/python

import getpass
import os
import requests
import json
from langchain.chat_models import init_chat_model

if not os.environ.get("GIT_PAT_AI"):
  os.environ["GIT_PAT_AI"] = getpass.getpass("Enter API key for Github: ")
else:
  GIT_TOKEN=os.environ["GIT_PAT_AI"]

if not os.environ.get("ANTHROPIC_API_KEY"):
  os.environ["ANTHROPIC_API_KEY"] = getpass.getpass("Enter API key for Anthropic: ")


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


model = init_chat_model("claude-3-5-sonnet-latest", model_provider="anthropic")

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
#response = model.invoke(f'Update the FROM command to be the latest baseimage version for {dockerfile.text}, return the updated dockerfile')
dockerfile_structured_model = model.with_structured_output(dockerfile_json_schema)
response = dockerfile_structured_model.invoke(f'Update the FROM command to be the latest baseimage version for {dockerfile.text}, return the updated dockerfile')
print("===========")
print(response["dockerfile"])
