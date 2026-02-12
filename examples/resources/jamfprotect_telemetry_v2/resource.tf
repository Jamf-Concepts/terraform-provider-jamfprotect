# A basic telemetry v2 configuration collecting common security events.
resource "jamfprotect_telemetry_v2" "default" {
  name                = "Default Telemetry"
  description         = "Collect common endpoint security events."
  log_files           = []
  log_file_collection = false
  performance_metrics = true
  file_hashing        = true

  events = [
    "authentication",
    "exec",
    "mount",
    "sudo",
    "login_login",
    "login_logout",
    "openssh_login",
    "openssh_logout",
  ]
}

# A telemetry v2 configuration with log file collection.
resource "jamfprotect_telemetry_v2" "with_logs" {
  name                = "Telemetry with Logs"
  description         = "Collect events and custom log files."
  log_file_collection = true
  performance_metrics = true
  file_hashing        = true

  log_files = [
    "/var/log/system.log",
    "/var/log/install.log",
  ]

  events = [
    "authentication",
    "exec",
    "sudo",
    "tcc_modify",
    "profile_add",
    "profile_remove",
  ]
}
