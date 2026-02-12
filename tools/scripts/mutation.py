#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx"]
# ///

import json
import os
import sys

import httpx


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def get_access_token(base_url: str, client_id: str, client_secret: str) -> str:
    token_url = f"{base_url.rstrip('/')}/token"
    payload = {"client_id": client_id, "password": client_secret}
    resp = httpx.post(token_url, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError("Token response missing access_token")
    return token


def graphql_post(
    base_url: str, token: str, query: str, variables: dict, path: str = "/graphql"
) -> dict:
    graphql_url = f"{base_url.rstrip('/')}{path}"
    payload = {"query": query, "variables": variables}
    headers = {"Authorization": token}
    resp = httpx.post(graphql_url, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data


CREATE_ANALYTIC_MUTATION = """
mutation createAnalytic($name: String!, $inputType: String!, $description: String!, $actions: [String], $analyticActions: [AnalyticActionsInput]!, $tags: [String]!, $categories: [String]!, $filter: String!, $context: [AnalyticContextInput]!, $level: Int!, $severity: SEVERITY!, $snapshotFiles: [String]!) {
  createAnalytic(
    input: {name: $name, inputType: $inputType, description: $description, actions: $actions, analyticActions: $analyticActions, tags: $tags, categories: $categories, filter: $filter, context: $context, level: $level, severity: $severity, snapshotFiles: $snapshotFiles}
  ) {
    ...AnalyticFields
    __typename
  }
}

fragment AnalyticFields on Analytic {
  uuid
  name
  label
  inputType
  filter
  description
  longDescription
  created
  updated
  actions
  analyticActions {
    name
    parameters
    __typename
  }
  tenantActions {
    name
    parameters
    __typename
  }
  tags
  level
  severity
  tenantSeverity
  snapshotFiles
  context {
    name
    type
    exprs
    __typename
  }
  categories
  jamf
  remediation
  __typename
}
"""

CREATE_ANALYTIC_VARIABLES = {
    "name": "Test Analytic",
    "inputType": "GPFSEvent",
    "filter": "",
    "description": "Test analytic",
    "actions": None,
    "analyticActions": [],
    "tags": [],
    "level": 0,
    "severity": "Informational",
    "snapshotFiles": [],
    "context": [],
    "categories": ["Evasion"],
}


def main() -> int:
    base_url = require_env("JAMFPROTECT_URL")
    client_id = require_env("JAMFPROTECT_CLIENT_ID")
    client_secret = require_env("JAMFPROTECT_CLIENT_SECRET")

    token = get_access_token(base_url, client_id, client_secret)
    result = graphql_post(
        base_url,
        token,
        CREATE_ANALYTIC_MUTATION,
        CREATE_ANALYTIC_VARIABLES,
        path="/app",
    )

    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
