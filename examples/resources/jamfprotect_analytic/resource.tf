resource "jamfprotect_analytic" "suspicious_process" {
  name        = "Detect Suspicious Process"
  input_type  = "GPProcessEvent"
  description = "Detect execution of suspicious binaries."
  filter      = "( $event.type == 1 )"
  level       = 5
  severity    = "High"

  tags           = ["security", "threat-hunting"]
  categories     = ["Execution"]
  snapshot_files = ["/usr/bin/malware"]

  analytic_actions = [{
    name = "SmartGroup"
    parameters = {
      id = "smartgroup"
    }
  }]

  context = [{
    name  = "process_path"
    type  = "String"
    exprs = ["$event.process.path"]
  }]
}
