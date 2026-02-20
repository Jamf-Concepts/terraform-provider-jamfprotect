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

# Example: Analytic with Custom Timeouts
# This example demonstrates how to configure custom timeout values for CRUD operations.
# By default, all operations use a 30-second timeout. You can override these for
# resources that may take longer to create, update, read, or delete.

resource "jamfprotect_analytic" "with_timeouts" {
  name        = "High-Volume Monitoring Analytic"
  description = "Analytics with many snapshot files may take longer to process"

  sensor_type = "File System Event"
  filter      = "( $event.type CONTAINS[c] 'sensitive' )"

  categories = ["DataExfiltration"]
  severity   = "High"
  level      = 9
  tags       = ["T1048", "ExfiltrationDetection"]
  snapshot_files = [
    "/Users/*/Documents/**/*",
    "/Users/*/Desktop/**/*",
    "/Users/*/Downloads/**/*",
    "/private/var/db/**/*",
    "/Library/Logs/**/*",
  ]

  context_item = [
    {
      name        = "FilePath"
      type        = "String"
      expressions = ["$event.file.path"]
    },
  ]

  # Custom timeout configuration
  # Useful when:
  # - Creating resources with complex configurations
  # - Network latency is higher than usual
  # - API response times are slower during peak usage
  # - Resources require additional processing time
  timeouts = {
    create = "2m" # Allow up to 2 minutes for creation
    read   = "1m" # Allow up to 1 minute for reads
    update = "2m" # Allow up to 2 minutes for updates
    delete = "1m" # Allow up to 1 minute for deletion
  }
}
