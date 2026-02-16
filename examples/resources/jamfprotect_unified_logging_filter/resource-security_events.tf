# Example: Unified Logging Filter for Security Events
# This example creates a unified logging filter to collect macOS unified log data
# for specific security-related subsystems.

resource "jamfprotect_unified_logging_filter" "security_events" {
  name        = "Security Event Logging"
  description = "Collect unified logs for security-related subsystems"

  # Process and subsystem filters
  process = ["com.apple.securityd", "com.apple.opendirectoryd"]

  subsystem = [
    "com.apple.security",
    "com.apple.authentication",
    "com.apple.authorization",
    "com.apple.loginwindow",
  ]

  # Category filters for specific event types
  category = ["authorization", "authentication", "audit"]

  # Predicate for advanced filtering
  predicate = "eventMessage CONTAINS 'authentication' OR eventMessage CONTAINS 'authorization'"
}
