## 0.1.0 (Unreleased)

FEATURES:

- **New Resource:** `jamfprotect_action_config` - Manage action configurations (alert data enrichment and reporting clients)
- **New Resource:** `jamfprotect_analytic` - Manage analytics (threat detection rules with filters, actions, and context)
- **New Resource:** `jamfprotect_plan` - Manage plans (endpoint security configurations with analytic sets, telemetry, and comms settings)
- **New Resource:** `jamfprotect_prevent_list` - Manage prevent lists (allow/block lists for team IDs, file hashes, CD hashes, and signing IDs)
- **New Resource:** `jamfprotect_unified_logging_filter` - Manage unified logging filters (Apple Unified Logging predicates)

All resources support full CRUD operations and `terraform import`.
