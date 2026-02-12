#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx"]
# ///
"""Query the /graphql endpoint (which supports introspection) for all custom
types referenced in the captured /app queries.  Outputs a summary of each type.
"""

import json
import os
import sys

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
      ofType { kind name }
    }
  }
}
"""

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
    return resp.json()["access_token"]


def type_ref_str(t: dict | None) -> str:
    if t is None:
        return "?"
    kind = t.get("kind", "")
    name = t.get("name")
    if kind == "NON_NULL":
        return f"{type_ref_str(t.get('ofType'))}!"
    if kind == "LIST":
        return f"[{type_ref_str(t.get('ofType'))}]"
    return name or "?"


# All custom types we need definitions for
TYPES_TO_LOOKUP = [
    "SEVERITY",
    "PREVENT_LIST_TYPE",
    "UNIFIED_LOGGING_LEVEL",
    "LOG_LEVEL_ENUM",
    "OrderDirection",
    "USBCONTROL_MOUNT_ACTION_TYPE_ENUM",
    "ANALYTIC_SET_TYPE",
    "ES_EVENTS_ENUM",
    "ActionConfigsOrderField",
    "AnalyticSetOrderField",
    "PlanOrderField",
    "PreventListOrderField",
    "TelemetryOrderField",
    "UnifiedLoggingFiltersOrderField",
    "USBControlOrderField",
    "AnalyticActionsInput",
    "AnalyticContextInput",
    "CommsConfigInput",
    "InfoSyncInput",
    "SignaturesFeedConfigInput",
    "PlanAnalyticSetInput",
    "USBControlRuleInput",
    "ActionConfigsAlertConfigInput",
    "ReportClientInput",
    "PreventListFilterInput",
    "UnifiedLoggingFiltersFilterInput",
    "AnalyticSetFiltersInput",
]


def main() -> int:
    base_url = require_env("JAMFPROTECT_URL")
    client_id = require_env("JAMFPROTECT_CLIENT_ID")
    client_secret = require_env("JAMFPROTECT_CLIENT_SECRET")

    token = get_access_token(base_url, client_id, client_secret)
    graphql_url = f"{base_url.rstrip('/')}/graphql"
    headers = {"Authorization": token}

    found = {}
    not_found = []

    for type_name in TYPES_TO_LOOKUP:
        resp = httpx.post(
            graphql_url,
            json={"query": TYPE_QUERY, "variables": {"name": type_name}},
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        type_def = data.get("data", {}).get("__type")
        if type_def is None:
            not_found.append(type_name)
        else:
            found[type_name] = type_def

    # Print summary
    for name in sorted(found):
        t = found[name]
        kind = t["kind"]
        if kind == "ENUM":
            vals = [e["name"] for e in (t.get("enumValues") or [])]
            print(f"{name} (ENUM): {vals}")
        elif kind == "INPUT_OBJECT":
            print(f"{name} (INPUT_OBJECT):")
            for f in t.get("inputFields") or []:
                print(f"  - {f['name']}: {type_ref_str(f['type'])}")
        elif kind == "SCALAR":
            print(f"{name} (SCALAR)")
        else:
            print(f"{name} ({kind})")
        print()

    if not_found:
        print("=== NOT FOUND on /graphql (only exists on /app) ===")
        for name in not_found:
            print(f"  - {name}")

    # Save full JSON for reference
    output = {"found": found, "not_found": not_found}
    with open("tools/scripts/graphql_types.json", "w") as f:
        json.dump(output, f, indent=2, sort_keys=True)
        f.write("\n")
    print("\nFull JSON saved to tools/scripts/graphql_types.json", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
