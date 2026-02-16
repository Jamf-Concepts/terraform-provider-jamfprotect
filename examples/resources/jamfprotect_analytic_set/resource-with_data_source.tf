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
