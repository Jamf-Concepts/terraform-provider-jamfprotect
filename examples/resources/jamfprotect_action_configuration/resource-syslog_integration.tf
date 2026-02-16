# Example: Action Configuration with Syslog Integration
# This example demonstrates forwarding alerts to a syslog server for centralized logging.

resource "jamfprotect_action_configuration" "syslog_integration" {
  name        = "Syslog Centralized Logging"
  description = "Forward high-severity alerts to central syslog server"

  # Minimal data collection for syslog alerts
  alert_data_collection = {
    binary_included_data_attributes                = ["Sha256", "Signing Information"]
    download_event_included_data_attributes        = ["File"]
    file_included_data_attributes                  = ["Sha256", "Signing Information"]
    file_system_event_included_data_attributes     = ["File", "Process"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process", "Destination Process"]
    process_included_data_attributes               = ["Binary", "User", "Group"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process"]
    user_included_data_attributes                  = ["Name"]
  }

  # Syslog endpoint with TLS encryption
  syslog_endpoints = [
    {
      collect_alerts = ["high", "medium"]
      collect_logs   = []
      host           = "syslog.example.com"
      port           = 6514
      protocol       = "tls"
    },
  ]

  # Local log file for backup and debugging
  log_file_endpoint = {
    collect_alerts   = ["high", "medium", "low"]
    collect_logs     = []
    path             = "/var/log/jamf-protect-alerts.log"
    ownership        = "root:wheel"
    permissions      = "0640"
    max_file_size_mb = 100
    max_backups      = 5
  }

  # Jamf Cloud for informational alerts and telemetry
  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["low", "informational"]
    collect_logs       = ["telemetry", "unified_logs"]
    destination_filter = null
  }
}
