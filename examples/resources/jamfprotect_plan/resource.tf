resource "jamfprotect_plan" "example" {
  action_configuration          = "1"
  advanced_threat_controls      = "Block and report"
  analytic_sets                 = ["7b88be75-78e3-4682-bbd8-4e16b2209105"]
  auto_update                   = true
  communications_protocol       = "MQTT:443"
  compliance_baseline_reporting = true
  description                   = "Managed by Terraform"
  endpoint_threat_prevention    = "Block and report"
  exception_sets                = ["4c8552c0-8347-43fb-b74b-eda602d02e15"]
  log_level                     = "Error"
  name                          = "Example Plan"
  removable_storage_control_set = "166"
  report_architecture           = true
  report_hostname               = true
  report_kernel_version         = true
  report_memory_size            = true
  report_model_name             = true
  report_os_version             = true
  report_serial_number          = true
  reporting_interval            = 1440
  tamper_prevention             = "Block and report"
  telemetry                     = "37"
  timeouts                      = null
}
