# Example: Action Configuration with HTTP Endpoint
# This example shows how to configure alert forwarding to an external HTTP endpoint
# such as a SIEM, SOAR, or webhook integration.

resource "jamfprotect_action_configuration" "http_integration" {
  name        = "HTTP Endpoint Integration"
  description = "Forward high-severity alerts to external SIEM via HTTP"

  # Alert data enrichment configuration
  alert_data_collection = {
    binary_included_data_attributes                = ["Sha1", "Sha256", "Signing Information", "Is App Bundle"]
    download_event_included_data_attributes        = ["File", "Process"]
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
