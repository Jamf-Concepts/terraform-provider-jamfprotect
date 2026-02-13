# List all unified logging filters in Jamf Protect.
data "jamfprotect_unified_logging_filters" "all" {}

# Output the names and enabled status of all unified logging filters.
output "logging_filter_summary" {
  value = [for f in data.jamfprotect_unified_logging_filters.all.unified_logging_filters : {
    name    = f.name
    enabled = f.enabled
  }]
}
