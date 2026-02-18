resource "jamfprotect_action_configuration" "example" {
  name        = "Example Action Configuration"
  description = "This is an example action configuration created by Terraform."
  alert_data_collection = {
    binary_included_data_attributes                     = ["Sha1", "Sha256", "Extended Attributes", "Is App Bundle", "Is Screenshot", "Is Quarantined", "Is Download", "Is Directory", "Downloaded From", "Signing Information", "User", "Group"]
    download_event_included_data_attributes             = ["File"]
    file_included_data_attributes                       = ["Sha1", "Sha256", "Extended Attributes", "Is App Bundle", "Is Screenshot", "Is Quarantined", "Is Download", "Is Directory", "Downloaded From", "Signing Information", "User", "Group"]
    file_system_event_included_data_attributes          = ["File", "Process", "User", "Group"]
    gatekeeper_event_included_data_attributes           = ["Blocked Process", "Blocked Binary"]
    group_included_data_attributes                      = ["Name"]
    keylog_register_event_included_data_attributes      = ["Source Process", "Destination Process"]
    malware_removal_tool_event_included_data_attributes = []
    process_included_data_attributes                    = ["Args", "Is GUI App", "Signing Information", "App Path", "Binary", "User", "Group", "Parent", "Process Group Leader"]
    process_event_included_data_attributes              = ["Process"]
    screenshot_event_included_data_attributes           = ["File"]
    synthetic_click_event_included_data_attributes      = ["Process", "User", "Group"]
    usb_event_included_data_attributes                  = []
    user_included_data_attributes                       = ["Name"]
  }
  http_endpoints = [
    {
      collect_alerts          = ["medium"]
      collect_logs            = []
      events_per_batch        = 2
      batching_window_seconds = 1
      event_delimiter         = "\n"
      max_batch_size_bytes    = 1100
      url                     = "https://example.com"
      method                  = "POST"
      headers = [
        {
          header = "Content-Type"
          value  = "application/json"
        },
      ]
    },
  ]
  kafka_endpoints = [
    {
      collect_alerts = []
      collect_logs   = ["telemetry"]
      host           = "example.com"
      port           = 9093
      topic          = "EXAMPLE"
      client_cn      = "EXAMPLE_CLIENT"
      server_cn      = "EXAMPLE_SERVER"
    },
  ]
  syslog_endpoints = [
    {
      collect_alerts = ["high"]
      collect_logs   = []
      host           = "example.com"
      port           = 6514
      protocol       = "tls"
    },
  ]
  log_file_endpoint = {
    collect_alerts   = ["high", "medium", "low", "informational"]
    collect_logs     = ["telemetry", "unified_logs"]
    path             = "/var/log/JamfProtect.log"
    ownership        = "root:wheel"
    permissions      = "0640"
    max_file_size_mb = 50
    max_backups      = 10
  }
  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["informational", "low", "medium", "high"]
    collect_logs       = ["telemetry", "unified_logs"]
    destination_filter = null
  }
}
