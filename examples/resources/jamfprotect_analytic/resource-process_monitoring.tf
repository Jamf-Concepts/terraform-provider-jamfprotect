# Example: Process Monitoring Analytic
# This example monitors for suspicious process execution patterns that may
# indicate malicious activity or privilege escalation attempts.

resource "jamfprotect_analytic" "suspicious_process_execution" {
  name        = "Suspicious Process Execution"
  description = "Detects execution of processes commonly used in attacks"

  sensor_type = "Process Event"
  filter      = "( $event.process.name IN { 'nc', 'netcat', 'curl', 'wget' } ) AND ( $event.process.args CONTAINS '-e' OR $event.process.args CONTAINS '/bin/bash' OR $event.process.args CONTAINS '/bin/sh' )"

  categories = ["Execution", "CommandAndControl"]
  severity   = "High"
  level      = 9

  tags = ["ReverseShell", "T1059", "NetworkTools"]

  snapshot_files = [
    "/tmp/*",
    "/var/tmp/*",
  ]

  add_to_jamf_pro_smart_group     = true
  jamf_pro_smart_group_identifier = "suspicious-execution-detected"

  context_item = [
    {
      name        = "ProcessName"
      type        = "String"
      expressions = ["$event.process.name"]
    },
    {
      name        = "ProcessPath"
      type        = "String"
      expressions = ["$event.process.path"]
    },
    {
      name        = "Arguments"
      type        = "String"
      expressions = ["$event.process.args"]
    },
    {
      name        = "ParentProcess"
      type        = "String"
      expressions = ["$event.process.parent.name"]
    },
    {
      name        = "User"
      type        = "String"
      expressions = ["$event.process.user.name"]
    },
  ]
}
