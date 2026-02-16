# Example: Analytic with Custom Timeouts
# This example demonstrates how to configure custom timeout values for CRUD operations.
# By default, all operations use a 30-second timeout. You can override these for
# resources that may take longer to create, update, read, or delete.

resource "jamfprotect_analytic" "with_timeouts" {
  name        = "High-Volume Monitoring Analytic"
  description = "Analytics with many snapshot files may take longer to process"

  sensor_type = "GPFSEvent"
  predicate   = "( $event.type CONTAINS[c] 'sensitive' )"

  categories = ["DataExfiltration"]
  severity   = "High"
  level      = 9
  tags       = ["T1048", "ExfiltrationDetection"]
  snapshot_files = [
    "/Users/*/Documents/**/*",
    "/Users/*/Desktop/**/*",
    "/Users/*/Downloads/**/*",
    "/private/var/db/**/*",
    "/Library/Logs/**/*",
  ]

  context_item = [
    {
      name        = "FilePath"
      type        = "String"
      expressions = ["$event.file.path"]
    },
  ]

  # Custom timeout configuration
  # Useful when:
  # - Creating resources with complex configurations
  # - Network latency is higher than usual
  # - API response times are slower during peak usage
  # - Resources require additional processing time
  timeouts {
    create = "2m" # Allow up to 2 minutes for creation
    read   = "1m" # Allow up to 1 minute for reads
    update = "2m" # Allow up to 2 minutes for updates
    delete = "1m" # Allow up to 1 minute for deletion
  }
}
