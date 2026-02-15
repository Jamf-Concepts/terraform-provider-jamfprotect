resource "jamfprotect_telemetry" "example" {
  collect_diagnostic_and_crash_reports = false
  collect_performance_metrics          = true
  description                          = "Managed by Terraform"
  file_hashes                          = true
  log_access_and_authentication        = false
  log_apple_security                   = false
  log_applications_and_processes       = false
  log_file_path                        = ["/path/to/example.log"]
  log_hardware_and_software            = false
  log_persistence                      = true
  log_system                           = true
  log_users_and_groups                 = true
  name                                 = "Example"
}
