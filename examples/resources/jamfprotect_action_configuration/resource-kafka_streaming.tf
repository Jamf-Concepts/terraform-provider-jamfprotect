# Example: Action Configuration with Kafka Integration
# This example shows how to stream telemetry data to Apache Kafka for real-time analysis.

resource "jamfprotect_action_configuration" "kafka_telemetry" {
  name        = "Kafka Streaming Integration"
  description = "Stream telemetry data to Kafka for real-time analytics"

  # Full data collection for telemetry
  alert_data_collection = {
    binary_included_data_attributes                = ["Sha1", "Sha256", "Signing Information", "Is App Bundle", "Extended Attributes"]
    download_event_included_data_attributes        = ["File", "Process", "User", "Downloaded From"]
    file_included_data_attributes                  = ["Sha1", "Sha256", "Extended Attributes", "Is Quarantined", "Is Download", "Downloaded From", "Signing Information"]
    file_system_event_included_data_attributes     = ["File", "Process", "User", "Group"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process", "Blocked Binary"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process", "Destination Process"]
    process_included_data_attributes               = ["Args", "Is GUI App", "Signing Information", "App Path", "Binary", "User", "Group", "Parent", "Process Group Leader"]
    process_event_included_data_attributes         = ["Process", "User", "Group"]
    screenshot_event_included_data_attributes      = ["File", "Process"]
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
