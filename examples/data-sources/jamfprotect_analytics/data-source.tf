# List all analytics in Jamf Protect.
data "jamfprotect_analytics" "all" {}

# Output the names and severity of all analytics.
output "analytic_summary" {
  value = [for a in data.jamfprotect_analytics.all.analytics : {
    name     = a.name
    severity = a.severity
  }]
}
