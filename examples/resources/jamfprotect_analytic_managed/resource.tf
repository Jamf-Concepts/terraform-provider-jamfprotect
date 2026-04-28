# Example: Imuler Malware Detection Jamf Managed Analytic
# This example demonstrates configuring the Jamf Managed Analytic for Imuler Malware Detection.
# Jamf Managed Analytics are pre-configured analytics provided by Jamf that must be imported.
# Once imported, they can be updated in a limited manner.

resource "jamfprotect_analytic_managed" "imulermalware" {
  tenant_actions = [
    {
      name = "Report"
    },
    {
      name = "SmartGroup"
      parameters = {
        id = "detection-group-imulermalware" # Unique identifier for the Smart Group
      }
    },
  ]
  tenant_severity = "High"
}
