## 0.1.0 (Unreleased)

FEATURES:

- **New Resource:** `jamfprotect_action_config` - Manage action configurations (alert data enrichment and reporting clients)
- **New Resource:** `jamfprotect_analytic` - Manage analytics (threat detection rules with filters, actions, and context)
- **New Resource:** `jamfprotect_analytic_set` - Manage analytic sets (grouped analytics with report/prevent types)
- **New Resource:** `jamfprotect_exception_set` - Manage exception sets (analytics and endpoint security exceptions)
- **New Resource:** `jamfprotect_plan` - Manage plans (endpoint security configurations with analytic sets, telemetry, and comms settings)
- **New Resource:** `jamfprotect_prevent_list` - Manage prevent lists (allow/block lists for team IDs, file hashes, CD hashes, and signing IDs)
- **New Resource:** `jamfprotect_telemetry_v2` - Manage telemetry v2 configurations (endpoint security event collection)
- **New Resource:** `jamfprotect_unified_logging_filter` - Manage unified logging filters (Apple Unified Logging predicates)
- **New Resource:** `jamfprotect_usb_control_set` - Manage USB control sets (USB device access policies)
- **New Data Source:** `jamfprotect_action_configs` - List all action configurations
- **New Data Source:** `jamfprotect_analytics` - List all analytics
- **New Data Source:** `jamfprotect_analytic_sets` - List all analytic sets
- **New Data Source:** `jamfprotect_exception_sets` - List all exception sets
- **New Data Source:** `jamfprotect_plans` - List all plans
- **New Data Source:** `jamfprotect_prevent_lists` - List all prevent lists
- **New Data Source:** `jamfprotect_telemetries_v2` - List all telemetry v2 configurations
- **New Data Source:** `jamfprotect_unified_logging_filters` - List all unified logging filters
- **New Data Source:** `jamfprotect_usb_control_sets` - List all USB control sets

All resources support full CRUD operations and `terraform import`.
