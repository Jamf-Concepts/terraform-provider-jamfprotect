# Terraform Provider for Jamf Protect

The Jamf Protect Terraform provider allows you to manage [Jamf Protect](https://www.jamf.com/products/jamf-protect/) resources via the Jamf Protect GraphQL API. Built using the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework) v1.17.0 (Protocol v6).

## Supported Resources

| Resource                             | Description                               |
| ------------------------------------ | ----------------------------------------- |
| `jamfprotect_analytic`               | Manage analytics (threat detection rules) |
| `jamfprotect_prevent_list`           | Manage prevent lists (allow/block lists)  |
| `jamfprotect_unified_logging_filter` | Manage unified logging filters            |

All resources support full CRUD operations and `terraform import`.

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

### Analytic

```hcl
resource "jamfprotect_analytic" "example" {
  name        = "Example Analytic"
  description = "Detects example events"
  input_type  = "Predicate"
  filter      = "process.name == 'example'"
  level       = "Default"
  severity    = 1
  tags        = ["example"]
  categories  = ["Visibility"]

  analytic_actions {
    name       = "Log"
    parameters = "{}"
  }

  context {
    name  = "process"
    type  = "String"
    exprs = ["process.name"]
  }
}
```

### Prevent List

```hcl
resource "jamfprotect_prevent_list" "example" {
  name        = "Example Prevent List"
  description = "Allow list for trusted apps"
  type        = "PATH"
  tags        = ["example"]
  list        = ["/usr/local/bin/trusted-app"]
}
```

### Unified Logging Filter

```hcl
resource "jamfprotect_unified_logging_filter" "example" {
  name        = "Example Filter"
  description = "Captures auth events"
  filter      = "subsystem == 'com.apple.Authorization'"
  level       = "Default"
  tags        = ["auth"]
  enabled     = true
}
```

## Building The Provider

1. Clone the repository
2. Enter the repository directory
3. Build the provider:

```shell
go install
```

## Developing the Provider

### Dependencies

This provider uses [Go modules](https://github.com/golang/go/wiki/Modules). To add a new dependency:

```shell
go get github.com/author/dependency
go mod tidy
```

### Testing

**Unit tests** (no API credentials required):

```shell
make test
```

**Acceptance tests** (creates real resources — requires `JAMFPROTECT_URL`, `JAMFPROTECT_CLIENT_ID`, `JAMFPROTECT_CLIENT_SECRET`):

```shell
make testacc
```

### Documentation

Generate or update documentation:

```shell
make generate
```
