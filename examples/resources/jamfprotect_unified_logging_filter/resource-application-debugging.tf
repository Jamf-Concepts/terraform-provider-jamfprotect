# Example: Unified Logging Filter for Application Debugging
# This example focuses on collecting detailed application logs for troubleshooting
# and debugging purposes.

resource "jamfprotect_unified_logging_filter" "application_debugging" {
  name        = "Application Debug Logging"
  description = "Collect detailed logs for application troubleshooting"

  # Application-specific processes
  process = [
    "com.mycompany.app",
    "com.mycompany.daemon",
  ]

  # Application subsystems
  subsystem = [
    "com.mycompany.app.networking",
    "com.mycompany.app.database",
    "com.mycompany.app.ui",
  ]

  # Debug and error categories
  category = ["debug", "error", "fault"]

  # Filter for error conditions
  predicate = "messageType == 'error' OR messageType == 'fault'"
}
