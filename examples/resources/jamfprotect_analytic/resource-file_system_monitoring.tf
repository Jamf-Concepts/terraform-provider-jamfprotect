# Example: File System Monitoring Analytic
# This example demonstrates monitoring sensitive file system locations for
# unauthorized modifications or access attempts.

resource "jamfprotect_analytic" "sensitive_file_access" {
  name        = "Sensitive File Modification"
  description = "Alerts when critical system files or configuration files are modified"

  sensor_type = "File System Event"
  filter      = "( $event.type CONTAINS 'Write' ) AND ( $event.file.path BEGINSWITH '/etc/' OR $event.file.path BEGINSWITH '/Library/LaunchDaemons/' )"

  categories = ["DefenseEvasion", "Persistence"]
  severity   = "Medium"
  level      = 7

  tags = ["FileIntegrity", "T1222", "ConfigProtection"]

  snapshot_files = [
    "/etc/hosts",
    "/etc/passwd",
    "/Library/LaunchDaemons/*",
  ]

  add_to_jamf_pro_smart_group     = true
  jamf_pro_smart_group_identifier = "config-tampering-detected"

  context_item = [
    {
      name        = "ModifiedFile"
      type        = "String"
      expressions = ["$event.file.path"]
    },
    {
      name        = "EventType"
      type        = "String"
      expressions = ["$event.type"]
    },
    {
      name        = "ModifyingProcess"
      type        = "String"
      expressions = ["$event.process.name"]
    },
    {
      name        = "FileHash"
      type        = "String"
      expressions = ["$event.file.sha256hex"]
    },
  ]
}
