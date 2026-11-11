## 0.13.0 (Unreleased)

FEATURES:

- **New Resource:** `jamfprotect_prevent_list_set` - Manage prevent list sets (grouped custom prevent lists, scoped to plans)
- **New Data Source:** `jamfprotect_prevent_list_sets` - List prevent list sets
- **New List Resource:** `jamfprotect_prevent_list_set` - Discover prevent list sets with `terraform query`

ENHANCEMENTS:

- `jamfprotect_plan`, `data.jamfprotect_plans`: new `prevent_list_sets` attribute. A custom prevent list now reaches an endpoint only when it belongs to a prevent list set assigned to that endpoint's plan, so a list created without a set takes effect on no endpoint. Leave the attribute unset to keep the sets Jamf Protect already assigned to the plan, or set it to `[]` to assign none.
- `data.jamfprotect_custom_prevent_lists`: new `sets` attribute listing the prevent list sets each list belongs to.
- `jamfprotect_role`: added the permission `Prevent List Sets`.

- Bumped jamfprotect-go-sdk to v0.10.0 and moved the provider's JSON handling to `encoding/json/v2`. Encoded action and client parameters are now deterministic, so key order no longer varies between runs.

BUG FIXES:

- `jamfprotect_group`, `jamfprotect_user`: `role_ids` (and `group_ids` on users) are now optional and computed. A configuration that omits them keeps the roles and groups already assigned, instead of sending an empty list on every apply and clearing them. Set an attribute to `[]` to clear it explicitly. State for an unset attribute is now an empty set rather than null.
- `jamfprotect_api_client`: no change in behaviour, now covered by tests. An unset `role_ids` creates the client with no roles. Jamf Protect assigns the Full Admin role when `roleIds` is left out of the request, so the provider always sends it.

## 0.12.0 (2026-10-06)

ENHANCEMENTS:

- Bumped Go to 1.27.1.
- Bumped jamfprotect-go-sdk to v0.9.0. Debug logs (`TF_LOG=debug` or `trace`) no longer contain API client passwords, data forwarding keys, HTTP endpoint URLs or header values. The client re-authenticates once when the API rejects a token, and bounds response size and pagination.
- `jamfprotect_role`: added the permissions `Data Loss Prevention Policies`, `Endpoint Security Exceptions`, `Packages`, `Unified Logging Filter Sets` and `Uninstaller Tokens`.

BUG FIXES:

- `jamfprotect_plan`: a configuration that omits `exception_sets` or `analytic_sets` now keeps the plan's current membership when another attribute changes; previously, sets attached outside Terraform were detached. Setting either attribute to `[]` now clears it instead of failing with an inconsistent result.
- `jamfprotect_plan`: `advanced_threat_controls` and `tamper_prevention` now identify the Jamf-managed analytic sets by the API's managed flag, so a custom analytic set with the same name is reported in `analytic_sets` instead of being treated as the managed set.
- `jamfprotect_plan`: the documentation example now uses valid values for `endpoint_threat_prevention`, `advanced_threat_controls`, `tamper_prevention` and `communications_protocol`.
- `jamfprotect_action_configuration`: `http_endpoints[*].url` and `headers[*].value` are now sensitive, so they no longer appear in plan or apply output. Each header gains a write-only `value_wo` with `value_wo_version` (Terraform 1.11+), which keeps the value out of state. Header values are no longer read back from Jamf Protect: after an import, or a change made outside Terraform, a header value is null until the next apply sets it from configuration. Outputs that reference these attributes need `sensitive = true`.
- `jamfprotect_action_configuration`: Read and import now fail with an error instead of silently dropping an endpoint the schema cannot represent: a second JamfCloud or LogFile endpoint, an unknown endpoint type, or an unknown report type. Previously the next apply deleted it.
- `jamfprotect_analytic_managed`: updates no longer fail with "Provider produced inconsistent result after apply" on `long_description`/`remediation`. A Jamf analytic with no tenant override now reads `tenant_actions` as null and leaves it out of updates, rather than sending an empty override; state written by earlier versions converges on the next refresh with no diff.
- `jamfprotect_analytic`, `jamfprotect_analytics`, `jamfprotect_analytic_managed`: the filter is now stored exactly as Jamf Protect returns it, so filters containing `\\` apply cleanly and changes that only double backslashes show as drift. State that holds a collapsed filter shows a one-time diff to the tenant's real value on the next plan.
- `jamfprotect_analytic`, `jamfprotect_analytics`: new computed `analytic_actions` attribute. Updates keep actions other than SmartGroup (for example ones added in the Jamf Protect console) instead of removing them.
- `jamfprotect_telemetry`: a `log_*` category now reads `true` only when every event in it is collected, so a partially collected category shows a diff that restores it. The new `additional_events` attribute keeps collected events that no category covers, and they are no longer dropped on update. The `jamfprotect_telemetries` data source exposes the same list.
- `jamfprotect_role`, `data.jamfprotect_roles`: an `Exception` permission granted without `Exception Sets` is now shown as `"Exception"` and appears as drift, rather than being hidden.
- `jamfprotect_set_computer_plan`: the action now fails when `plan_id` does not exist, or when Jamf Protect does not record the assignment. Previously it reported success while nothing was assigned.
- `jamfprotect_exception_set`: an exception set with no `exceptions` now applies, instead of failing with "Provider produced inconsistent result after apply".
- Provider debug logs (`TF_LOG=debug` or `trace`) mask the configured `client_secret` in every logged HTTP field.

## 0.11.0 (2026-08-07)

FEATURES:

- **New Resource:** `jamfprotect_unified_logging_filter_set` - Manage unified logging filter sets (grouped unified logging filters, scoped to plans)
- **New Data Source:** `jamfprotect_unified_logging_filter_sets` - List all unified logging filter sets, with their member filters and the plans they are assigned to

Unified logging filters now reach endpoints through filter set membership plus plan assignment, rather than the filter's own `enabled` flag. `jamfprotect_plan` gains a `unified_logging_filter_sets` attribute for that assignment, and `enabled` on `jamfprotect_unified_logging_filter` is retained for backwards compatibility but no longer affects delivery.

Existing `jamfprotect_plan` configurations are unaffected. Jamf Protect's migration collects a tenant's previously enabled filters into a set named `Default` and assigns it to every existing plan; because `unified_logging_filter_sets` is optional and computed, a configuration that omits it adopts whatever is already assigned instead of diffing against it. Set it to `[]` to explicitly assign none. A filter set assigned to a plan cannot be deleted, so detach it from every plan before destroying it.

## 0.10.0 (2026-07-29)

FEATURES:

- **New Action:** `jamfprotect_set_computer_plan` - Move one or more computers to a different plan, with an opt-in `wait_for_checkin` that blocks until each agent has settled on the new plan
- **New Action:** `jamfprotect_delete_computer` - Remove one or more computer records from the tenant (destructive and irreversible; does not uninstall the agent)

Actions require Terraform >= 1.14. Both computer actions target computers with `computer_uuids` sourced from the `jamfprotect_computers` data source, and are idempotent — an empty target set or an already-deleted computer warns rather than failing, so an offboarding pipeline is safe to re-run. Terraform has no destroy-time action events, so the primary workflow is direct invocation: `terraform apply -invoke=action.jamfprotect_delete_computer.<name>` to clear a retiring plan's computers before `terraform destroy`, which Jamf Protect otherwise blocks with a dependency error.

Note that a pending plan move does not release the old plan: `deletePlan` stays blocked until the Jamf Protect agent has applied the change, which is what `wait_for_checkin` on `jamfprotect_set_computer_plan` waits for.

## 0.9.0 (2026-07-10)

ENHANCEMENTS:

- **List Resources:** Added an opt-in `exclude_builtins` configuration attribute to list resources for resource types that have Jamf-provided built-in / system instances (`jamfprotect_analytic`, `jamfprotect_analytic_set`, `jamfprotect_exception_set`, `jamfprotect_plan`, `jamfprotect_role`, `jamfprotect_action_configuration`, `jamfprotect_group`). It defaults to `false` (all instances, including built-ins, are returned); set it to `true` (in a nested `config {}` block) to exclude built-ins from `terraform query` results — e.g. the Default plan, Full Admin / Read Only roles, Default Analytic Set, Default action configuration, Jamf Managed Default Exceptions, and the Default group. Data sources are unchanged.

## 0.1.0 (2026-03-05)

FEATURES:

- **New Resource:** `jamfprotect_custom_prevent_list` - Manage custom prevent lists (allow/block lists for team IDs, file hashes, CD hashes, and signing IDs)
- **New Resource:** `jamfprotect_telemetry` - Manage telemetry configurations (endpoint security event collection)
- **New Resource:** `jamfprotect_removable_storage_control_set` - Manage removable storage control sets (device access policies)
- **New Data Source:** `jamfprotect_custom_prevent_lists` - List all custom prevent lists
- **New Data Source:** `jamfprotect_telemetries` - List all telemetry configurations
- **New Data Source:** `jamfprotect_removable_storage_control_sets` - List all removable storage control sets

## 0.0.1 (2026-02-13)

FEATURES:

- **New Resource:** `jamfprotect_action_config` - Manage action configurations (alert data enrichment and reporting clients)
- **New Resource:** `jamfprotect_analytic` - Manage analytics (threat detection rules with filters, actions, and context)
- **New Resource:** `jamfprotect_analytic_set` - Manage analytic sets (grouped analytics with report/prevent types)
- **New Resource:** `jamfprotect_exception_set` - Manage exception sets (analytics and endpoint security exceptions)
- **New Resource:** `jamfprotect_plan` - Manage plans (endpoint security configurations with analytic sets, telemetry, and comms settings)
- **New Resource:** `jamfprotect_unified_logging_filter` - Manage unified logging filters (Apple Unified Logging predicates)
- **New Data Source:** `jamfprotect_action_configs` - List all action configurations
- **New Data Source:** `jamfprotect_analytics` - List all analytics
- **New Data Source:** `jamfprotect_analytic_sets` - List all analytic sets
- **New Data Source:** `jamfprotect_exception_sets` - List all exception sets
- **New Data Source:** `jamfprotect_plans` - List all plans
- **New Data Source:** `jamfprotect_unified_logging_filters` - List all unified logging filters

All resources support full CRUD operations and `terraform import`.
