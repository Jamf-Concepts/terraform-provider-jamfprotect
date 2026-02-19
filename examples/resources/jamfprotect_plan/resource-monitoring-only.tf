# Example: Plan with Report-Only Mode
# This example shows a monitoring-only plan suitable for testing or low-risk environments
# where you want visibility without blocking potentially legitimate activity.

resource "jamfprotect_action_configuration" "monitoring" {
  name        = "Monitoring Action Config"
  description = "Basic monitoring configuration"

  alert_data_collection = {
    binary_included_data_attributes                = ["Signing Information"]
    download_event_included_data_attributes        = ["File"]
    file_included_data_attributes                  = ["Sha256"]
    file_system_event_included_data_attributes     = ["File", "Process"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process"]
    process_included_data_attributes               = ["Binary", "User"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process"]
    user_included_data_attributes                  = ["Name"]
  }

  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["high", "medium"]
    collect_logs       = ["telemetry"]
    destination_filter = null
  }
}

resource "jamfprotect_plan" "monitoring_only" {
  name        = "Monitoring Only Plan"
  description = "Report-only mode for testing and monitoring without blocking"

  action_configuration = jamfprotect_action_configuration.monitoring.id

  auto_update = true

  communications_protocol = "mqtt"

  reporting_interval   = 1440 # 24 hours
  report_architecture  = false
  report_hostname      = true
  report_serial_number = false

  # All threat prevention in report-only mode
  endpoint_threat_prevention = "ReportOnly"
  advanced_threat_controls   = "ReportOnly"
  tamper_prevention          = "ReportOnly"
}
