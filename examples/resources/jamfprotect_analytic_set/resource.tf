resource "jamfprotect_analytic_set" "example" {
  name        = "My Custom Analytic Set"
  description = "A collection of custom analytics for detecting suspicious activity"

  # Types of analytics in this set (optional)
  types = ["Report", "Prevent"]

  # List of analytic UUIDs to include in this set
  analytics = [
    "dcb69719-5ae1-46f6-972a-da1799daa00c",
    "ec930ae1-1796-11ea-b2ba-acde48001122",
    "a0ae8850-902a-4d46-b06b-27973939136f"
  ]

  timeouts {
    create = "5m"
    update = "5m"
    delete = "2m"
  }
}

# Reference analytics from the analytics data source
data "jamfprotect_analytics" "all" {}

resource "jamfprotect_analytic_set" "from_datasource" {
  name        = "Auto-Generated Set"
  description = "Analytics filtered from data source"

  # Filter analytics by tag
  analytics = [
    for analytic in data.jamfprotect_analytics.all.analytics :
    analytic.id if contains(analytic.tags, "critical")
  ]
}
