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


SCHEMA_FIELDS_QUERY = """
{
  schema_type: __type(name: "__Schema") {
    kind
    name
  }
  type_type: __type(name: "__Type") {
    kind
    name
  }
  query_type: __type(name: "Query") {
    kind
    name
  }
  mutation_type: __type(name: "Mutation") {
    kind
    name
  }
  analytic_type: __type(name: "Analytic") {
    kind
    name
  }
  analytic_input: __type(name: "AnalyticActionsInput") {
    kind
    name
  }
  analytic_context_input: __type(name: "AnalyticContextInput") {
    kind
    name
  }
}
"""


def main() -> int:
    base_url = require_env("JAMFPROTECT_URL")
    client_id = require_env("JAMFPROTECT_CLIENT_ID")
    client_secret = require_env("JAMFPROTECT_CLIENT_SECRET")

    token = get_access_token(base_url, client_id, client_secret)

    graphql_url = f"{base_url.rstrip('/')}/app"
    payload = {"query": SCHEMA_FIELDS_QUERY, "variables": {}}
    headers = {"Authorization": token}
    resp = httpx.post(graphql_url, json=payload, headers=headers, timeout=60)
    print(f"Status: {resp.status_code}", file=sys.stderr)
    resp.raise_for_status()
    data = resp.json()

    if "errors" in data:
        print(f"Errors: {json.dumps(data['errors'], indent=2)}", file=sys.stderr)
        # Still print any partial data
        if "data" in data:
            json.dump(data["data"], sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        return 1

    json.dump(data["data"], sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
