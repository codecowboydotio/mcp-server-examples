#!/usr/bin/python

import getpass
import os
import requests

if not os.environ.get("GIT_PAT_AI"):
  os.environ["GIT_PAT_AI"] = getpass.getpass("Enter API key for Github: ")
else:
  GIT_TOKEN=os.environ["GIT_PAT_AI"]

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
  print(query_answer.text)



