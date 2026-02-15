# Terraform Provider for Jamf Protect

> [!NOTE]
> This provider is in early development (v0.1.0). All resources have been tested via acceptance tests against a real Jamf Protect tenant. However, the API surface is subject to change as we gather feedback from the community.

The Jamf Protect Terraform provider allows you to manage [Jamf Protect](https://www.jamf.com/products/jamf-protect/) resources via the Jamf Protect GraphQL API. Built using the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework) v1.17.0 (Protocol v6).

## Supported Resources

| Resource                             | Description                                    |
| ------------------------------------ | ---------------------------------------------- |
| `jamfprotect_action_config`          | Manage action configurations                   |
| `jamfprotect_analytic`               | Manage analytics (threat detection rules)      |
| `jamfprotect_analytic_set`           | Manage analytic sets (grouped analytics)       |
| `jamfprotect_exception_set`          | Manage exception sets (analytic exceptions)    |
| `jamfprotect_plan`                   | Manage plans (endpoint configurations)         |
| `jamfprotect_custom_prevent_list`    | Manage custom prevent lists (allow/block lists) |
| `jamfprotect_telemetry_v2`           | Manage telemetry v2 configurations             |
| `jamfprotect_unified_logging_filter` | Manage unified logging filters                 |
| `jamfprotect_removable_storage_control_set` | Manage removable storage control sets (device access policy) |

All resources support full CRUD operations and `terraform import`.

## Supported Data Sources

| Data Source                              | Description                                  |
| ---------------------------------------- | -------------------------------------------- |
| `jamfprotect_action_configs`             | List all action configurations               |
| `jamfprotect_analytics`                  | List all analytics (threat detection rules)   |
| `jamfprotect_analytic_sets`              | List all analytic sets (grouped analytics)    |
| `jamfprotect_exception_sets`             | List all exception sets (analytic exceptions) |
| `jamfprotect_plans`                      | List all plans (endpoint configurations)      |
| `jamfprotect_custom_prevent_lists`       | List all custom prevent lists (allow/block lists) |
| `jamfprotect_telemetries_v2`             | List all telemetry v2 configurations          |
| `jamfprotect_unified_logging_filters`    | List all unified logging filters              |
| `jamfprotect_removable_storage_control_sets` | List all removable storage control sets        |

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.25 (to build the provider)

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

## Usage Examples

### Action Configuration

```hcl
resource "jamfprotect_action_config" "default" {
  name        = "Default Action Config"
  description = "Default alert data enrichment settings."

  alert_config = {
    data = {
      binary                = { attrs = ["signingInfo", "isAppBundle"], related = ["process"] }
      click_event           = { attrs = [], related = [] }
      download_event        = { attrs = ["sourceUrl"], related = ["file", "process"] }
      file                  = { attrs = ["sha256hex", "path"], related = [] }
      fs_event              = { attrs = ["path"], related = ["process", "file"] }
      group                 = { attrs = [], related = [] }
      proc_event            = { attrs = ["ppid", "uid"], related = ["process"] }
      process               = { attrs = ["name", "path", "pid"], related = ["binary", "user"] }
      screenshot_event      = { attrs = [], related = [] }
      usb_event             = { attrs = [], related = [] }
      user                  = { attrs = ["name", "uid"], related = [] }
      gk_event              = { attrs = [], related = [] }
      keylog_register_event = { attrs = [], related = [] }
      mrt_event             = { attrs = [], related = [] }
    }
  }
}
```

### Analytic

```hcl
resource "jamfprotect_analytic" "suspicious_process" {
  name        = "Detect Suspicious Process"
  input_type  = "GPProcessEvent"
  description = "Detect execution of suspicious binaries."
  filter      = "( $event.type == 1 )"
  level       = 5
  severity    = "High"

  tags           = ["security", "threat-hunting"]
  categories     = ["Execution"]
  snapshot_files = []

  analytic_actions = [{
    name       = "SmartGroup"
    parameters = "{\"id\":\"smartgroup\"}"
  }]

  context = [{
    name  = "process_path"
    type  = "String"
    exprs = ["$event.process.path"]
  }]
}
```

### Plan

```hcl
resource "jamfprotect_plan" "endpoint_security" {
  name           = "Endpoint Security Plan"
  description    = "Standard endpoint security plan with threat prevention."
  action_configs = jamfprotect_action_config.default.id
  auto_update    = true

  comms_config = {
    fqdn     = "your-tenant.protect.jamfcloud.com"
    protocol = "mqtt"
  }

  info_sync = {
    attrs                  = ["arch", "hostName", "serial"]
    insights_sync_interval = 86400
  }

  signatures_feed_config = {
    mode = "blocking"
  }
}
```

### Prevent List

```hcl
resource "jamfprotect_custom_prevent_list" "trusted_team_ids" {
  name        = "Trusted Team IDs"
  description = "Allow list for trusted developer teams"
  prevent_type = "TEAMID"
  list_data   = ["ABC123DEF4"]
}
```

### Unified Logging Filter

```hcl
resource "jamfprotect_unified_logging_filter" "auth_events" {
  name        = "Auth Events"
  description = "Captures authentication events"
  filter      = "subsystem == \"com.apple.securityd\""
  level       = "DEFAULT"
  tags        = ["auth"]
  enabled     = true
}
```

## Building The Provider

1. Clone the repository
2. Enter the repository directory
3. Build the provider:

```shell
mise run build
```

## Developing the Provider

### Dependencies

This provider uses [Go modules](https://github.com/golang/go/wiki/Modules). To add a new dependency:

```shell
go get github.com/author/dependency
mise run tidy
```

### Testing

**Unit tests** (no API credentials required):

```shell
mise run test
```

**Acceptance tests** (creates real resources -- requires `JAMFPROTECT_URL`, `JAMFPROTECT_CLIENT_ID`, `JAMFPROTECT_CLIENT_SECRET`):

```shell
mise run testacc
```

### Documentation

Generate or update documentation:

```shell
mise run build:generate-docs
```

## Publishing to Terraform Registry

The provider is published to the [Terraform Registry](https://registry.terraform.io/providers/smithjw/jamfprotect) via GitHub releases with GPG-signed checksums.

### Prerequisites

1. **Terraform Registry account**: Sign in at [registry.terraform.io](https://registry.terraform.io) with your GitHub account and authorize the `smithjw` namespace.
2. **GPG signing key**: Generate a GPG key pair and add the public key to the Terraform Registry under [User Settings > Signing Keys](https://registry.terraform.io/settings/gpg-keys). The private key and passphrase must be stored as GitHub Actions secrets (`GPG_PRIVATE_KEY`, `PASSPHRASE`).
3. **GitHub repository settings**: Ensure the repository is public and the release workflow has write access to contents.

### Release Process

1. Ensure all tests pass:

   ```shell
   mise run check
   ```

2. Regenerate documentation and verify no drift:

   ```shell
   mise run build:generate-docs
   git diff --exit-code
   ```

3. Create and push a version tag:

   ```shell
   git tag v0.1.0-alpha.1
   git push origin v0.1.0-alpha.1
   ```

4. The [release workflow](.github/workflows/release.yml) automatically:
   - Builds binaries for all supported platforms (linux, darwin, windows, freebsd × amd64, arm64, etc.)
   - Generates SHA256 checksums and signs them with GPG
   - Creates a GitHub release with the binaries, checksums, and Terraform registry manifest
   - The Terraform Registry detects the new release and publishes it

### Using the Alpha Provider

```hcl
terraform {
  required_providers {
    jamfprotect = {
      source  = "smithjw/jamfprotect"
      version = "0.1.0-alpha.1"
    }
  }
}
```
