#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx"]
# ///

import argparse
import json
import os
import sys
from typing import Iterable

import httpx


TYPE_REF_FRAGMENT = """
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
"""


FIELDS_QUERY = (
    """
query IntrospectionFields {
  __schema {
    queryType {
      name
      fields {
        name
        args { name type { ...TypeRef } }
        type { ...TypeRef }
      }
    }
    mutationType {
      name
      fields {
        name
        args { name type { ...TypeRef } }
        type { ...TypeRef }
      }
    }
  }
}
"""
    + TYPE_REF_FRAGMENT
)


TYPE_QUERY = (
    """
query IntrospectionType($name: String!) {
  __type(name: $name) {
    kind
    name
    description
    fields {
      name
      description
      args { name type { ...TypeRef } }
      type { ...TypeRef }
    }
    inputFields {
      name
      description
      type { ...TypeRef }
    }
    enumValues {
      name
      description
    }
  }
}
"""
    + TYPE_REF_FRAGMENT
)


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


def graphql_post(base_url: str, token: str, query: str, variables: dict) -> dict:
    graphql_url = f"{base_url.rstrip('/')}/graphql"
    payload = {"query": query, "variables": variables}
    headers = {"Authorization": token}
    resp = httpx.post(graphql_url, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data


def unwrap_type(type_ref: dict | None) -> str | None:
    if not type_ref:
        return None
    current = type_ref
    while current.get("ofType") is not None:
        current = current["ofType"]
    return current.get("name")


def collect_type_names(fields: Iterable[dict]) -> set[str]:
    names: set[str] = set()
    for field in fields:
        names.add(unwrap_type(field.get("type")))
        for arg in field.get("args", []):
            names.add(unwrap_type(arg.get("type")))
    return {name for name in names if name}


def collect_type_names_from_type(type_def: dict | None) -> set[str]:
    if not type_def:
        return set()
    names: set[str] = set()
    for field in type_def.get("fields", []) or []:
        names.add(unwrap_type(field.get("type")))
        for arg in field.get("args", []) or []:
            names.add(unwrap_type(arg.get("type")))
    for input_field in type_def.get("inputFields", []) or []:
        names.add(unwrap_type(input_field.get("type")))
    return {name for name in names if name}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Describe Jamf Protect GraphQL fields and types"
    )
    parser.add_argument(
        "--field",
        dest="fields",
        action="append",
        default=[],
        help="Field name to describe (repeatable)",
    )
    parser.add_argument(
        "--output",
        help="Optional output path for JSON (defaults to stdout)",
    )
    parser.add_argument(
        "--type",
        dest="types",
        action="append",
        default=[],
        help="Type name to include (repeatable)",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Recursively include referenced types",
    )
    args = parser.parse_args()

    base_url = require_env("JAMFPROTECT_URL")
    client_id = require_env("JAMFPROTECT_CLIENT_ID")
    client_secret = require_env("JAMFPROTECT_CLIENT_SECRET")

    token = get_access_token(base_url, client_id, client_secret)
    schema_data = graphql_post(base_url, token, FIELDS_QUERY, {})

    schema = schema_data.get("data", {}).get("__schema", {})
    query_fields = schema.get("queryType", {}).get("fields", []) or []
    mutation_fields = schema.get("mutationType", {}).get("fields", []) or []

    selected_fields = []
    if args.fields:
        for field in query_fields + mutation_fields:
            if field.get("name") in args.fields:
                selected_fields.append(field)
    else:
        selected_fields = query_fields + mutation_fields

    type_names = collect_type_names(selected_fields)
    type_names.update(args.types)
    types: dict[str, dict] = {}

    remaining = {name for name in type_names if name}
    while remaining:
        name = remaining.pop()
        if name in types:
            continue
        type_data = graphql_post(base_url, token, TYPE_QUERY, {"name": name})
        type_def = type_data.get("data", {}).get("__type")
        types[name] = type_def
        if args.deep:
            referenced = collect_type_names_from_type(type_def)
            remaining.update(referenced.difference(types.keys()))

    output = {
        "fields": selected_fields,
        "types": types,
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2, sort_keys=True)
            handle.write("\n")
    else:
        json.dump(output, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
