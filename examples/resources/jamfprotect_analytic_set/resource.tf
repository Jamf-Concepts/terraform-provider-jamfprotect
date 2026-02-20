# Example: Analytic Set Using Data Source
# This example demonstrates referencing existing analytics from a data source
# rather than creating new ones.

data "jamfprotect_analytics" "existing" {
  # Filter for analytics with specific tags
  # The data source will return all available analytics
}

# Create an analytic set using existing analytics found via data source
resource "jamfprotect_analytic_set" "compliance_monitoring" {
  name        = "Compliance Monitoring Set"
  description = "Curated set of analytics for regulatory compliance"

  # Reference specific analytics by their known IDs
  # These IDs would typically come from a data source or be known values
  analytics = [
    "3c8a88ef-277a-4238-a695-ebaa6eee0921",
    "dcb69719-5ae1-46f6-972a-da1799daa00c",
  ]
}

# Example: Analytic Set with Multiple Analytics
# This example shows how to group multiple related analytics into a set
# for easier management and deployment.

resource "jamfprotect_analytic_set" "security_monitoring" {
  name        = "Comprehensive Security Monitoring"
  description = "Collection of analytics for detecting common security threats"

  analytics = [
    jamfprotect_analytic.privilege_escalation.id,
    jamfprotect_analytic.suspicious_downloads.id,
    jamfprotect_analytic.sensitive_file_access.id,
  ]
}

# Reference the analytics from the examples above
resource "jamfprotect_analytic" "privilege_escalation" {
  name           = "Privilege Escalation Detection"
  description    = "Monitors for privilege escalation attempts"
  sensor_type    = "Process Event"
  filter         = "( $event.process.name == 'sudo' )"
  categories     = ["PrivilegeEscalation"]
  severity       = "High"
  level          = 8
  tags           = ["PrivEsc", "T1548"]
  snapshot_files = []
  context_item   = []
}

resource "jamfprotect_analytic" "suspicious_downloads" {
  name           = "Suspicious Download Detection"
  description    = "Monitors for downloads from untrusted sources"
  sensor_type    = "Download Event"
  filter         = "( $event.sourceUrl CONTAINS[c] '.untrusted' )"
  categories     = ["InitialAccess"]
  severity       = "Medium"
  level          = 6
  tags           = ["Downloads", "T1566"]
  snapshot_files = []
  context_item   = []
}

resource "jamfprotect_analytic" "sensitive_file_access" {
  name           = "Sensitive File Access"
  description    = "Monitors access to sensitive system files"
  sensor_type    = "File System Event"
  filter         = "( $event.file.path BEGINSWITH '/etc/' )"
  categories     = ["DefenseEvasion"]
  severity       = "Medium"
  level          = 5
  tags           = ["FileIntegrity", "T1222"]
  snapshot_files = []
  context_item   = []
}
