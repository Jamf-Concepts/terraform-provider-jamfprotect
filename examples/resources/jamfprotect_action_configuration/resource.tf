# Example: Action Configuration with HTTP Endpoint
# This example shows how to configure alert forwarding to an external HTTP endpoint
# such as a SIEM, SOAR, or webhook integration.

resource "jamfprotect_action_configuration" "http_integration" {
  name        = "HTTP Endpoint Integration"
  description = "Forward high-severity alerts to external SIEM via HTTP"

  # Alert data enrichment configuration
  alert_data_collection = {
    binary_included_data_attributes                = ["Sha1", "Sha256", "Signing Information", "Is App Bundle"]
    download_event_included_data_attributes        = ["File"]
    file_included_data_attributes                  = ["Sha1", "Sha256", "Signing Information", "Downloaded From"]
    file_system_event_included_data_attributes     = ["File", "Process", "User"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process", "Blocked Binary"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process", "Destination Process"]
    process_included_data_attributes               = ["Args", "Signing Information", "Binary", "User", "Group"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process", "User"]
    user_included_data_attributes                  = ["Name"]
  }

  # HTTP endpoint for external SIEM integration
  http_endpoints = [
    {
      collect_alerts          = ["high", "medium"]
      collect_logs            = []
      events_per_batch        = 100
      batching_window_seconds = 30
      event_delimiter         = "\n"
      max_batch_size_bytes    = 1048576 # 1 MB
      url                     = "https://siem.example.com/api/v1/alerts"
      method                  = "POST"
      headers = [
        {
          header = "Content-Type"
          value  = "application/json"
        },
        {
          header = "Authorization"
          value  = "Bearer YOUR_API_TOKEN"
        },
      ]
    },
  ]

  # Keep Jamf Protect Cloud endpoint for other alert severities and logs
  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["low", "informational"]
    collect_logs       = ["telemetry", "unified_logs"]
    destination_filter = null
  }
}

# Example: Action Configuration with Kafka Integration
# This example shows how to stream telemetry data to Apache Kafka for real-time analysis.

resource "jamfprotect_action_configuration" "kafka_telemetry" {
  name        = "Kafka Streaming Integration"
  description = "Stream telemetry data to Kafka for real-time analytics"

  # Full data collection for telemetry
  alert_data_collection = {
    binary_included_data_attributes                = ["Sha1", "Sha256", "Signing Information", "Is App Bundle", "Extended Attributes"]
    download_event_included_data_attributes        = ["File"]
    file_included_data_attributes                  = ["Sha1", "Sha256", "Extended Attributes", "Is Quarantined", "Is Download", "Downloaded From", "Signing Information"]
    file_system_event_included_data_attributes     = ["File", "Process", "User", "Group"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process", "Blocked Binary"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process", "Destination Process"]
    process_included_data_attributes               = ["Args", "Is GUI App", "Signing Information", "App Path", "Binary", "User", "Group", "Parent", "Process Group Leader"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process", "User", "Group"]
    user_included_data_attributes                  = ["Name"]
  }

  # Kafka endpoint for streaming telemetry
  kafka_endpoints = [
    {
      collect_alerts = []
      collect_logs   = ["telemetry", "unified_logs"]
      host           = "kafka.example.com"
      port           = 9093
      topic          = "jamf-protect-telemetry"
      client_cn      = "jamf-protect-client"
      server_cn      = "kafka-server"
    },
  ]

  # Keep high-priority alerts going to Jamf Cloud
  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["high", "medium", "low", "informational"]
    collect_logs       = []
    destination_filter = null
  }
}

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
