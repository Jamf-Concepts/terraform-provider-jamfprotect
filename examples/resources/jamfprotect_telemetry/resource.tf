# Example: Telemetry Configuration for Security Focus
# This example configures telemetry to collect security-relevant events
# while minimizing performance impact.

resource "jamfprotect_telemetry" "security_focused" {
  name        = "Security-Focused Telemetry"
  description = "Collect security-relevant telemetry for threat hunting"

  # Security-related logging
  log_access_and_authentication = true
  log_apple_security            = true
  log_persistence               = true
  log_users_and_groups          = true

  # System context
  log_system                = true
  log_hardware_and_software = false

  # Application monitoring
  log_applications_and_processes = true

  # File integrity monitoring
  file_hashes = true

  # Custom log file paths for specific applications
  log_file_path = [
    "/var/log/security.log",
    "/Library/Logs/DiagnosticReports/*.crash",
  ]

  # Performance metrics
  collect_performance_metrics          = false
  collect_diagnostic_and_crash_reports = true
}

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
