# Manage Jamf Protect data retention settings.
resource "jamfprotect_data_retention" "long_term" {
  informational_alert_days            = 365
  low_medium_high_severity_alert_days = 365
  archived_data_days                  = 365
}
