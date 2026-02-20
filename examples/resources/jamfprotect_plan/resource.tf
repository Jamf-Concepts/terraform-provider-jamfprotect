# Example: Plan with Enhanced Threat Prevention
# This example shows a security plan with aggressive threat prevention settings
# suitable for high-security environments.

resource "jamfprotect_action_configuration" "security_enrichment" {
  name        = "Security Data Enrichment"
  description = "Enhanced data collection for security analysis"

  alert_data_collection = {
    binary_included_data_attributes                = ["Sha1", "Sha256", "Signing Information", "Is App Bundle"]
    download_event_included_data_attributes        = ["File", "Downloaded From"]
    file_included_data_attributes                  = ["Sha1", "Sha256", "Is Quarantined", "Signing Information"]
    file_system_event_included_data_attributes     = ["File", "Process", "User"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process", "Destination Process"]
    process_included_data_attributes               = ["Args", "Signing Information", "App Path", "Binary", "User", "Group", "Parent"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process", "User"]
    user_included_data_attributes                  = ["Name"]
  }

  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["high", "medium", "low", "informational"]
    collect_logs       = ["telemetry", "unified_logs"]
    destination_filter = null
  }
}

resource "jamfprotect_plan" "high_security" {
  name        = "High Security Plan"
  description = "Aggressive threat prevention for sensitive workloads"

  action_configuration = jamfprotect_action_configuration.security_enrichment.id

  # Enable automatic updates
  auto_update = true

  # Communication protocol
  communications_protocol = "mqtt"

  # Reporting settings
  reporting_interval   = 720 # 12 hours
  report_architecture  = true
  report_hostname      = true
  report_serial_number = true

  # Threat prevention settings - Block mode
  endpoint_threat_prevention = "BlockAndReport"
  advanced_threat_controls   = "BlockAndReport"
  tamper_prevention          = "BlockAndReport"
}

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
