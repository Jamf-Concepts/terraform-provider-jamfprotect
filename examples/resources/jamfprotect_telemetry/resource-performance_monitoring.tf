# Example: Telemetry Configuration for Performance Monitoring
# This example prioritizes performance and diagnostic data collection
# over security event monitoring.

resource "jamfprotect_telemetry" "performance_monitoring" {
  name        = "Performance Monitoring Telemetry"
  description = "Collect performance metrics and diagnostic data"

  # Minimal security logging
  log_access_and_authentication = false
  log_apple_security            = false
  log_persistence               = false
  log_users_and_groups          = false

  # System and hardware monitoring
  log_system                = true
  log_hardware_and_software = true

  # Application monitoring for performance
  log_applications_and_processes = true

  # No file hashing (performance impact)
  file_hashes = false

  # Focus on performance and diagnostics
  collect_performance_metrics          = true
  collect_diagnostic_and_crash_reports = true

  # Application-specific logs
  log_file_path = [
    "/Library/Logs/DiagnosticReports/*.diag",
  ]
}
