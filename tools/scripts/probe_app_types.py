#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx"]
# ///
"""Probe the /app GraphQL endpoint to discover input types and enums.

Strategy:
1. For enum types: send a mutation/query that uses the enum with an
   obviously invalid value. The error message typically lists valid values.
2. For input object types: send a mutation with the input type set to an
   empty object or a scalar. The error message lists expected fields.
3. For order/filter types used in list queries: probe via those queries.
"""

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
    return resp.json()["access_token"]


def graphql_post_raw(base_url: str, token: str, query: str, variables: dict) -> dict:
    """Post to /app and return the full response (including errors)."""
    graphql_url = f"{base_url.rstrip('/')}/app"
    payload = {"query": query, "variables": variables}
    headers = {"Authorization": token}
    resp = httpx.post(graphql_url, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.json()


# --- Probes ---
# Each probe is a (query, variables) tuple designed to trigger a validation
# error that reveals type details.

PROBES: dict[str, tuple[str, dict]] = {
    # Enums - use invalid values to get allowed values listed in errors
    "SEVERITY": (
        'mutation { createAnalytic(input: {name:"x", inputType:"x", description:"x", filter:"x", analyticActions:[], tags:[], categories:[], context:[], level:0, severity: INVALID_VALUE, snapshotFiles:[]}) { uuid } }',
        {},
    ),
    "PREVENT_LIST_TYPE": (
        'mutation { createPreventList(input: {name:"x", tags:[], type: INVALID_VALUE, list:[]}) { id } }',
        {},
    ),
    "UNIFIED_LOGGING_LEVEL": (
        'mutation { createUnifiedLoggingFilter(input: {name:"x", tags:[], filter:"x", level: INVALID_VALUE}) { uuid } }',
        {},
    ),
    "LOG_LEVEL_ENUM": (
        "query { __type_probe: listPlans(input: {order: {direction: DESC, field: created}}) { items { logLevel } } }",
        {},
    ),
    "USBCONTROL_MOUNT_ACTION_TYPE_ENUM": (
        'mutation { createUSBControlSet(input: {name:"x", defaultMountAction: INVALID_VALUE, rules:[]}) { id } }',
        {},
    ),
    "ES_EVENTS_ENUM": (
        'mutation { createTelemetryV2(input: {name:"x", logFiles:[], logFileCollection:false, performanceMetrics:false, events:[INVALID_VALUE], fileHashing:false}) { id } }',
        {},
    ),
    "OrderDirection": (
        "query { listAnalytics(input: {order: {direction: INVALID_VALUE, field: created}}) { items { uuid } } }",
        {},
    ),
    "ANALYTIC_SET_TYPE": (
        # try from the /graphql schema describe we already have
        "query { listAnalyticSets(input: {order: {direction: DESC, field: created}}) { items { types } } }",
        {},
    ),
    # Order field enums
    "ActionConfigsOrderField": (
        "query { listActionConfigs(input: {order: {direction: DESC, field: INVALID_VALUE}}) { items { id } } }",
        {},
    ),
    "AnalyticSetOrderField": (
        "query { listAnalyticSets(input: {order: {direction: DESC, field: INVALID_VALUE}}) { items { uuid } } }",
        {},
    ),
    "PlanOrderField": (
        "query { listPlans(input: {order: {direction: DESC, field: INVALID_VALUE}}) { items { id } } }",
        {},
    ),
    "PreventListOrderField": (
        "query { listPreventLists(input: {order: {direction: DESC, field: INVALID_VALUE}}) { items { id } } }",
        {},
    ),
    "TelemetryOrderField": (
        "query { listTelemetries(input: {order: {direction: DESC, field: INVALID_VALUE}}) { items { id } } }",
        {},
    ),
    "UnifiedLoggingFiltersOrderField": (
        "query { listUnifiedLoggingFilters(input: {order: {direction: DESC, field: INVALID_VALUE}}) { items { uuid } } }",
        {},
    ),
    "USBControlOrderField": (
        "query { listUSBControlSets(input: {order: {direction: DESC, field: INVALID_VALUE}}) { items { id } } }",
        {},
    ),
    # Input objects - provide wrong types to learn expected fields
    "AnalyticActionsInput": (
        'mutation { createAnalytic(input: {name:"x", inputType:"x", description:"x", filter:"x", analyticActions:[{INVALID_FIELD: true}], tags:[], categories:[], context:[], level:0, severity: Informational, snapshotFiles:[]}) { uuid } }',
        {},
    ),
    "AnalyticContextInput": (
        'mutation { createAnalytic(input: {name:"x", inputType:"x", description:"x", filter:"x", analyticActions:[], tags:[], categories:[], context:[{INVALID_FIELD: true}], level:0, severity: Informational, snapshotFiles:[]}) { uuid } }',
        {},
    ),
    "CommsConfigInput": (
        'mutation { createPlan(input: {name:"x", description:"x", actionConfigs:"x", analyticSets:[], commsConfig:{INVALID_FIELD: true}, infoSync:{attrs:[]}, autoUpdate:false, signaturesFeedConfig:{mode: INVALID}}) { id } }',
        {},
    ),
    "InfoSyncInput": (
        'mutation { createPlan(input: {name:"x", description:"x", actionConfigs:"x", analyticSets:[], commsConfig:{fqdn:"x",protocol:"x"}, infoSync:{INVALID_FIELD: true}, autoUpdate:false, signaturesFeedConfig:{mode: INVALID}}) { id } }',
        {},
    ),
    "SignaturesFeedConfigInput": (
        'mutation { createPlan(input: {name:"x", description:"x", actionConfigs:"x", analyticSets:[], commsConfig:{fqdn:"x",protocol:"x"}, infoSync:{attrs:[]}, autoUpdate:false, signaturesFeedConfig:{INVALID_FIELD: true}}) { id } }',
        {},
    ),
    "PlanAnalyticSetInput": (
        'mutation { createPlan(input: {name:"x", description:"x", actionConfigs:"x", analyticSets:[{INVALID_FIELD: true}], commsConfig:{fqdn:"x",protocol:"x"}, infoSync:{attrs:[]}, autoUpdate:false, signaturesFeedConfig:{mode: INVALID}}) { id } }',
        {},
    ),
    "USBControlRuleInput": (
        'mutation { createUSBControlSet(input: {name:"x", defaultMountAction: ReadOnly, rules:[{INVALID_FIELD: true}]}) { id } }',
        {},
    ),
    "ActionConfigsAlertConfigInput": (
        'mutation { createActionConfigs(input: {name:"x", description:"x", alertConfig:{INVALID_FIELD: true}}) { id } }',
        {},
    ),
    "ReportClientInput": (
        'mutation { createActionConfigs(input: {name:"x", description:"x", alertConfig:{}, clients:[{INVALID_FIELD: true}]}) { id } }',
        {},
    ),
    # Filter input types
    "PreventListFilterInput": (
        "query { listPreventLists(input: {order: {direction: DESC, field: created}, filter: {INVALID_FIELD: true}}) { items { id } } }",
        {},
    ),
    "UnifiedLoggingFiltersFilterInput": (
        "query { listUnifiedLoggingFilters(input: {order: {direction: DESC, field: created}, filter: {INVALID_FIELD: true}}) { items { uuid } } }",
        {},
    ),
    "AnalyticSetFiltersInput": (
        "query { listAnalyticSets(input: {order: {direction: DESC, field: created}, filter: {INVALID_FIELD: true}}) { items { uuid } } }",
        {},
    ),
}


def main() -> int:
    base_url = require_env("JAMFPROTECT_URL")
    client_id = require_env("JAMFPROTECT_CLIENT_ID")
    client_secret = require_env("JAMFPROTECT_CLIENT_SECRET")

    token = get_access_token(base_url, client_id, client_secret)

    results: dict[str, list[dict]] = {}
    for type_name, (query, variables) in sorted(PROBES.items()):
        print(f"Probing {type_name}...", file=sys.stderr)
        try:
            data = graphql_post_raw(base_url, token, query, variables)
            if "errors" in data:
                results[type_name] = data["errors"]
            else:
                results[type_name] = [
                    {
                        "info": "No errors returned — query succeeded",
                        "data": data.get("data"),
                    }
                ]
        except Exception as exc:
            results[type_name] = [{"error": str(exc)}]

    json.dump(results, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
