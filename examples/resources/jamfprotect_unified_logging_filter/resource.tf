# Example: Unified Logging Filter for Security Events
# This example creates a unified logging filter to collect macOS unified log data
# for specific security-related subsystems.

resource "jamfprotect_unified_logging_filter" "security_events" {
  name        = "Security Event Logging"
  description = "Collect unified logs for security-related subsystems"
  filter      = "subsystem == \"com.apple.securityd\" OR subsystem == \"com.apple.opendirectoryd\""
  enabled     = true
  tags        = ["security", "authentication"]
}

# Example: Unified Logging Filter for Application Debugging
# This example focuses on collecting detailed application logs for troubleshooting
# and debugging purposes.

resource "jamfprotect_unified_logging_filter" "application_debugging" {
  name        = "Application Debug Logging"
  description = "Collect detailed logs for application troubleshooting"
  filter      = "subsystem BEGINSWITH \"com.mycompany\" AND (messageType == \"error\" OR messageType == \"fault\")"
  enabled     = true
  tags        = ["debugging", "application-logs"]
}
