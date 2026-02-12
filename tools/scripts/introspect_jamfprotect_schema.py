#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx"]
# ///

import json
import os
import sys

import httpx


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType {
      name
      fields {
        name
      }
    }
    mutationType {
      name
      fields {
        name
      }
    }
  }
}
"""


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


def run_introspection(base_url: str, token: str) -> dict:
    graphql_url = f"{base_url.rstrip('/')}/graphql"
    payload = {"query": INTROSPECTION_QUERY, "variables": {}}
    headers = {"Authorization": token}
    resp = httpx.post(graphql_url, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data


def main() -> int:
    base_url = require_env("JAMFPROTECT_URL")
    client_id = require_env("JAMFPROTECT_CLIENT_ID")
    client_secret = require_env("JAMFPROTECT_CLIENT_SECRET")

    token = get_access_token(base_url, client_id, client_secret)
    data = run_introspection(base_url, token)

    schema = data.get("data", {}).get("__schema", {})
    queries = sorted(
        {field["name"] for field in schema.get("queryType", {}).get("fields", [])}
    )
    mutations = sorted(
        {field["name"] for field in schema.get("mutationType", {}).get("fields", [])}
    )

    output = {
        "queryType": schema.get("queryType", {}).get("name"),
        "mutationType": schema.get("mutationType", {}).get("name"),
        "queries": queries,
        "mutations": mutations,
    }

    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
