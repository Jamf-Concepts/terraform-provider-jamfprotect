# Example: Analytic with Jamf Pro Smart Group Integration
# This example shows how to automatically add devices to a Jamf Pro Smart Group
# when an analytic triggers, enabling automated remediation workflows.

resource "jamfprotect_analytic" "gatekeeper_bypass" {
  name        = "Gatekeeper Bypass Attempt"
  description = "Detects attempts to bypass macOS Gatekeeper protection"

  sensor_type = "Gatekeeper Event"
  filter      = "( $event.gatekeeper.action CONTAINS 'Block' ) AND ( $event.gatekeeper.url != null )"

  categories = ["DefenseEvasion"]
  severity   = "High"
  level      = 9

  tags = ["Gatekeeper", "T1553", "SecurityBypass"]

  snapshot_files = []

  # Enable Jamf Pro Smart Group integration
  add_to_jamf_pro_smart_group     = true
  jamf_pro_smart_group_identifier = "gatekeeper-bypass-detected"

  context_item = [
    {
      name        = "BlockedApp"
      type        = "String"
      expressions = ["$event.process.name"]
    },
    {
      name        = "DownloadURL"
      type        = "String"
      expressions = ["$event.gatekeeper.url"]
    },
    {
      name        = "BlockReason"
      type        = "String"
      expressions = ["$event.gatekeeper.action"]
    },
  ]
}
