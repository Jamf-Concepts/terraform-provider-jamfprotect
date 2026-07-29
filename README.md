# Terraform Provider for Jamf Protect

> [!TIP]
> **📘 Start here — [Managing Jamf Protect with Terraform: The Jamf Protect Provider](https://concepts.jamf.com/en/guides/infrastructure-as-code/managing-jamf-protect-with-terraform-the-jamf-protect-provider/)**
>
> The official getting-started guide on Jamf Concepts. Covers why Jamf Protect has its own provider, what the provider covers, creating an API client, configuring the provider, defining and applying your first resources, and bringing an existing tenant under management with `terraform import` and list resources. New to this provider or to Terraform? Read that first.

This provider was originally created by [James Smith (@smithjw)](https://github.com/smithjw), who kindly donated the source code to [Jamf Concepts](https://github.com/Jamf-Concepts). Thank you, James, for your foundational work on this project.

The Jamf Protect Terraform provider allows you to manage [Jamf Protect](https://www.jamf.com/products/jamf-protect/) resources via the Jamf Protect GraphQL API. Built using the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework) v1.17.0 (Protocol v6).

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.13 (>= 1.14 for [actions](#supported-actions))

## Installation

The provider is published to the [Terraform Registry](https://registry.terraform.io/providers/Jamf-Concepts/jamfprotect). For a step-by-step walkthrough — from creating an API client through to applying your first configuration and importing an existing tenant — see the Jamf Concepts guide: [**Managing Jamf Protect with Terraform: The Jamf Protect Provider**](https://concepts.jamf.com/en/guides/infrastructure-as-code/managing-jamf-protect-with-terraform-the-jamf-protect-provider/).

Add the following to your Terraform configuration:

```hcl
terraform {
  required_providers {
    jamfprotect = {
      source = "Jamf-Concepts/jamfprotect"
    }
  }
}
```

## Authentication

The provider authenticates against the Jamf Protect API using an API client. Configure credentials via the provider block or environment variables:

| Provider Attribute | Environment Variable        | Description                                                 |
| ------------------ | --------------------------- | ----------------------------------------------------------- |
| `url`              | `JAMFPROTECT_URL`           | Base URL (e.g. `https://your-tenant.protect.jamfcloud.com`) |
| `client_id`        | `JAMFPROTECT_CLIENT_ID`     | API client ID                                               |
| `client_secret`    | `JAMFPROTECT_CLIENT_SECRET` | API client secret                                           |

### Example Provider Configuration

```hcl
provider "jamfprotect" {
  url           = "https://your-tenant.protect.jamfcloud.com"
  client_id     = var.jamfprotect_client_id
  client_secret = var.jamfprotect_client_secret
}
```

Or use environment variables and leave the provider block empty:

```hcl
provider "jamfprotect" {}
```

## Supported Resources

| Resource | Description |
| --- | --- |
| `jamfprotect_action_configuration` | Manage action configurations (alert data enrichment and reporting endpoints) |
| `jamfprotect_analytic` | Manage custom analytics (threat detection rules) |
| `jamfprotect_analytic_set` | Manage analytic sets (grouped analytics assigned to plans) |
| `jamfprotect_api_client` | Manage API clients |
| `jamfprotect_change_management` | Manage change management (configuration freeze) |
| `jamfprotect_custom_prevent_list` | Manage custom prevent lists (allow/block by Team ID, file hash, CDHash, or signing ID) |
| `jamfprotect_data_forwarding` | Manage data forwarding settings |
| `jamfprotect_data_retention` | Manage data retention settings |
| `jamfprotect_exception_set` | Manage exception sets (analytic and threat prevention exceptions) |
| `jamfprotect_group` | Manage groups |
| `jamfprotect_plan` | Manage plans (endpoint security configurations) |
| `jamfprotect_removable_storage_control_set` | Manage removable storage control sets (USB device access policies) |
| `jamfprotect_role` | Manage roles |
| `jamfprotect_telemetry` | Manage telemetry configurations (event collection and metrics) |
| `jamfprotect_unified_logging_filter` | Manage unified logging filters (macOS unified log predicates) |
| `jamfprotect_user` | Manage users |

All resources support full CRUD operations and `terraform import`.

> [!TIP]
> `jamfprotect_change_management`, `jamfprotect_data_forwarding`, and `jamfprotect_data_retention` are singleton resources — they manage tenant-wide settings rather than individually identifiable objects.

## Supported Data Sources

| Data Source | Description |
| --- | --- |
| `jamfprotect_action_configurations` | List all action configurations |
| `jamfprotect_analytics` | List all analytics (built-in and custom) |
| `jamfprotect_analytic_sets` | List all analytic sets |
| `jamfprotect_api_clients` | List all API clients |
| `jamfprotect_computer` | Look up a single enrolled computer by UUID |
| `jamfprotect_computers` | List all enrolled computers |
| `jamfprotect_custom_prevent_lists` | List all custom prevent lists |
| `jamfprotect_downloads` | Retrieve Jamf Protect installer and profile download URLs |
| `jamfprotect_exception_sets` | List all exception sets |
| `jamfprotect_groups` | List all groups |
| `jamfprotect_identity_providers` | List all identity providers |
| `jamfprotect_plan_configuration_profile` | Generate a configuration profile (.mobileconfig) for a plan |
| `jamfprotect_plans` | List all plans |
| `jamfprotect_removable_storage_control_sets` | List all removable storage control sets |
| `jamfprotect_roles` | List all roles |
| `jamfprotect_telemetries` | List all telemetry configurations |
| `jamfprotect_unified_logging_filters` | List all unified logging filters |
| `jamfprotect_users` | List all users |

## Supported Actions

Actions cover imperative operations that Terraform should not model as managed resources, because the provider does not own the object's lifecycle. Both actions below target computers with `computer_uuids`, sourced from the `jamfprotect_computers` data source — a single-element set for one computer, or a `for` expression for a whole fleet in one invocation.

| Action | Description |
| --- | --- |
| `jamfprotect_set_computer_plan` | Move one or more computers to a different plan, optionally waiting for the agent to check in |
| `jamfprotect_delete_computer` | Remove one or more computer records from the tenant (destructive and irreversible) |

Actions require Terraform >= 1.14. Terraform has no destroy-time action events, so these are primarily invoked directly:

```shell
# Clear a retiring plan's computers so the plan itself can be destroyed —
# Jamf Protect blocks deletePlan while computers are still assigned to it.
terraform apply -invoke=action.jamfprotect_delete_computer.offboard
terraform destroy
```

## Usage Examples

### Action Configuration

```hcl
resource "jamfprotect_action_configuration" "default" {
  name        = "Default Action Config"
  description = "Alert data enrichment with cloud delivery."

  alert_data_collection = {
    binary_included_data_attributes                = ["Sha256", "Signing Information"]
    download_event_included_data_attributes        = ["File"]
    file_included_data_attributes                  = ["Sha256", "Signing Information"]
    file_system_event_included_data_attributes     = ["File", "Process"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process"]
    process_included_data_attributes               = ["Args", "Signing Information", "Binary", "User", "Parent"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process"]
    user_included_data_attributes                  = ["Name"]
  }

  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["low", "medium", "high"]
    collect_logs       = ["telemetry"]
    destination_filter = null
  }
}
```

### Plan

```hcl
resource "jamfprotect_plan" "endpoint_security" {
  name        = "Endpoint Security Plan"
  description = "Standard endpoint security plan with threat prevention."

  action_configuration = jamfprotect_action_configuration.default.id
  telemetry            = jamfprotect_telemetry.standard.id

  exception_sets = [
    jamfprotect_exception_set.baseline.id,
  ]

  endpoint_threat_prevention = "Block and report"
  advanced_threat_controls   = "Block and report"
  tamper_prevention          = "Block and report"

  reporting_interval            = 1440
  compliance_baseline_reporting = true
  auto_update                   = true
  communications_protocol       = "MQTT:443"
  log_level                     = "Error"

  report_architecture   = true
  report_hostname       = true
  report_serial_number  = true
  report_kernel_version = false
  report_memory_size    = false
  report_model_name     = true
  report_os_version     = true
}
```

### Custom Prevent List

```hcl
resource "jamfprotect_custom_prevent_list" "trusted_team_ids" {
  name         = "Trusted Team IDs"
  description  = "Allow list for trusted developer teams."
  prevent_type = "Team ID"
  list_data    = ["ABC123DEF4"]
}
```

### Unified Logging Filter

```hcl
resource "jamfprotect_unified_logging_filter" "auth_events" {
  name        = "Auth Events"
  description = "Captures authentication events."
  filter      = "subsystem == \"com.apple.securityd\""
  tags        = ["auth"]
  enabled     = true
}
```

### Removable Storage Control Set

```hcl
resource "jamfprotect_removable_storage_control_set" "strict" {
  name                               = "Strict USB Policy"
  description                        = "Block all removable storage. YubiKeys are allowed."
  default_permission                 = "Prevent"
  default_local_notification_message = "Removable storage devices are not permitted."

  override_vendor_id = [
    {
      vendor_ids = ["0x1050"]
      permission = "Read and Write"
      apply_to   = "All"
    },
  ]
}
```

### Configuration Profile Export

```hcl
data "jamfprotect_plan_configuration_profile" "this" {
  id = jamfprotect_plan.endpoint_security.id

  sign_profile                           = false
  include_pppc_payload                   = true
  include_system_extension_payload       = true
  include_login_background_items_payload = true
  include_websocket_authorizer_key       = true
  include_root_ca_certificate            = true
  include_csr_certificate                = true
  include_bootstrap_token                = true
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing instructions, and contribution guidelines.

## Feedback & Discussion

Please contact the project principles via [GitHub Issues](https://github.com/Jamf-Concepts/terraform-provider-jamfprotect/issues).

The Jamf Terraform community has discussions in #terraform-provider-jamfprotect on [MacAdmins Slack](https://www.macadmins.org/). Join the conversation!

## Included components

The following third party acknowledgements and licenses are incorporated by reference:

- [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework) ([MPL](https://github.com/hashicorp/terraform-plugin-framework?tab=MPL-2.0-1-ov-file))
- [Terraform Plugin Framework Timeouts](https://github.com/hashicorp/terraform-plugin-framework-timeouts) ([MPL](https://github.com/hashicorp/terraform-plugin-framework-timeouts?tab=MPL-2.0-1-ov-file))
- [Terraform Plugin Framework Validators](https://github.com/hashicorp/terraform-plugin-framework-validators) ([MPL](https://github.com/hashicorp/terraform-plugin-framework-validators?tab=MPL-2.0-1-ov-file))
- [Terraform Plugin Go](https://github.com/hashicorp/terraform-plugin-go) ([MPL](https://github.com/hashicorp/terraform-plugin-go?tab=MPL-2.0-1-ov-file))
- [Terraform Plugin Log](https://github.com/hashicorp/terraform-plugin-log) ([MPL](https://github.com/hashicorp/terraform-plugin-log?tab=MPL-2.0-1-ov-file))
- [Terraform Plugin Testing](https://github.com/hashicorp/terraform-plugin-testing) ([MPL](https://github.com/hashicorp/terraform-plugin-testing?tab=MPL-2.0-1-ov-file))
- [Go Retryable HTTP](https://github.com/hashicorp/go-retryablehttp) ([MPL](https://github.com/hashicorp/go-retryablehttp?tab=MPL-2.0-1-ov-file))
- [Jamf Protect Go SDK](https://github.com/Jamf-Concepts/jamfprotect-go-sdk) ([MIT](https://github.com/Jamf-Concepts/jamfprotect-go-sdk?tab=MIT-1-ov-file))
- [Go UUID](https://github.com/hashicorp/go-uuid) ([MPL](https://github.com/hashicorp/go-uuid?tab=MPL-2.0-1-ov-file))

&nbsp;

*Copyright 2026, Jamf Software LLC.*
