# Timeout Configuration

All resources in the Jamf Protect Terraform Provider support configurable timeouts for CRUD operations.

## Default Timeouts

By default, all operations use a **30-second timeout**:
- Create: 30 seconds
- Read: 30 seconds
- Update: 30 seconds
- Delete: 30 seconds

These defaults are defined in `internal/common/constants/timeouts.go`.

## Configuring Custom Timeouts

Users can override the default timeouts in their Terraform configuration using the `timeouts` block:

```hcl
resource "jamfprotect_analytic" "example" {
  name        = "My Analytic"
  description = "Example with custom timeouts"
  # ... other required attributes ...

  timeouts {
    create = "2m"   # 2 minutes for creation
    read   = "1m"   # 1 minute for reads
    update = "2m"   # 2 minutes for updates
    delete = "1m"   # 1 minute for deletion
  }
}
```

## When to Use Custom Timeouts

Consider increasing timeouts for:

1. **Complex Resources**: Resources with many nested configurations or large data sets
2. **Network Conditions**: When operating in environments with higher latency
3. **API Performance**: During peak usage times when the Jamf Protect API may be slower
4. **Bulk Operations**: When creating resources that trigger significant backend processing

## Supported Time Units

Terraform supports the following time units in timeout values:
- `s` - seconds (e.g., `30s`)
- `m` - minutes (e.g., `2m`)
- `h` - hours (e.g., `1h`)

Examples:
- `"30s"` - 30 seconds
- `"1m30s"` - 1 minute and 30 seconds
- `"2m"` - 2 minutes

## Resources Supporting Timeouts

All resources in this provider support timeout configuration:
- `jamfprotect_analytic`
- `jamfprotect_analytic_set`
- `jamfprotect_action_configuration`
- `jamfprotect_plan`
- `jamfprotect_exception_set`
- `jamfprotect_custom_prevent_list`
- `jamfprotect_telemetry`
- `jamfprotect_unified_logging_filter`
- `jamfprotect_removable_storage_control_set`

## Implementation Details

The provider uses the [terraform-plugin-framework-timeouts](https://github.com/hashicorp/terraform-plugin-framework-timeouts) module to implement timeout support. The timeouts are applied using Go's `context.WithTimeout` to ensure API calls respect the configured limits.

## Example: Resource with Extended Timeouts

```hcl
resource "jamfprotect_plan" "enterprise" {
  name                 = "Enterprise Security Plan"
  description          = "Complex plan with extended timeout"
  action_configuration = jamfprotect_action_config.enterprise.id
  
  # ... many configuration options ...
  
  # Extended timeouts for complex resource
  timeouts {
    create = "5m"
    read   = "2m"
    update = "5m"
    delete = "2m"
  }
}
```

## See Also

- [Terraform Timeout Documentation](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts)
- [Example: Analytic with Custom Timeouts](./jamfprotect_analytic/with_custom_timeouts.tf)
