## 0.1.0 (Unreleased)

FEATURES:

- **New Resource:** `jamfprotect_action_config` - Manage action configurations (alert data enrichment and reporting clients)
- **New Resource:** `jamfprotect_analytic` - Manage analytics (threat detection rules with filters, actions, and context)
- **New Resource:** `jamfprotect_analytic_set` - Manage analytic sets (grouped analytics with report/prevent types)
- **New Resource:** `jamfprotect_exception_set` - Manage exception sets (analytics and endpoint security exceptions)
- **New Resource:** `jamfprotect_plan` - Manage plans (endpoint security configurations with analytic sets, telemetry, and comms settings)
- **New Resource:** `jamfprotect_custom_prevent_list` - Manage custom prevent lists (allow/block lists for team IDs, file hashes, CD hashes, and signing IDs)
- **New Resource:** `jamfprotect_telemetry` - Manage telemetry configurations (endpoint security event collection)
- **New Resource:** `jamfprotect_unified_logging_filter` - Manage unified logging filters (Apple Unified Logging predicates)
- **New Resource:** `jamfprotect_removable_storage_control_set` - Manage removable storage control sets (device access policies)
- **New Data Source:** `jamfprotect_action_configs` - List all action configurations
- **New Data Source:** `jamfprotect_analytics` - List all analytics
- **New Data Source:** `jamfprotect_analytic_sets` - List all analytic sets
- **New Data Source:** `jamfprotect_exception_sets` - List all exception sets
- **New Data Source:** `jamfprotect_plans` - List all plans
- **New Data Source:** `jamfprotect_custom_prevent_lists` - List all custom prevent lists
- **New Data Source:** `jamfprotect_telemetries` - List all telemetry configurations
- **New Data Source:** `jamfprotect_unified_logging_filters` - List all unified logging filters
- **New Data Source:** `jamfprotect_removable_storage_control_sets` - List all removable storage control sets
- **New Action:** `jamfprotect_set_computer_plan` - Move one or more computers to a different plan, with an opt-in `wait_for_checkin` that blocks until each agent has settled on the new plan
- **New Action:** `jamfprotect_delete_computer` - Remove one or more computer records from the tenant (destructive and irreversible; does not uninstall the agent)

All resources support full CRUD operations and `terraform import`.

Actions require Terraform >= 1.14. Both computer actions target computers with `computer_uuids` sourced from the `jamfprotect_computers` data source, and are idempotent — an empty target set or an already-deleted computer warns rather than failing, so an offboarding pipeline is safe to re-run. Terraform has no destroy-time action events, so the primary workflow is direct invocation: `terraform apply -invoke=action.jamfprotect_delete_computer.<name>` to clear a retiring plan's computers before `terraform destroy`, which Jamf Protect otherwise blocks with a dependency error.

Note that a pending plan move does not release the old plan: `deletePlan` stays blocked until the Jamf Protect agent has applied the change, which is what `wait_for_checkin` on `jamfprotect_set_computer_plan` waits for.

ENHANCEMENTS:

- **List Resources:** Added an opt-in `exclude_builtins` configuration attribute to list resources for resource types that have Jamf-provided built-in / system instances (`jamfprotect_analytic`, `jamfprotect_analytic_set`, `jamfprotect_exception_set`, `jamfprotect_plan`, `jamfprotect_role`, `jamfprotect_action_configuration`, `jamfprotect_group`). It defaults to `false` (all instances, including built-ins, are returned); set it to `true` (in a nested `config {}` block) to exclude built-ins from `terraform query` results — e.g. the Default plan, Full Admin / Read Only roles, Default Analytic Set, Default action configuration, Jamf Managed Default Exceptions, and the Default group. Data sources are unchanged.
- Bumped Go to 1.26.5.
