provider "jamfprotect" {
  url           = "https://your-tenant.protect.jamfcloud.com"
  client_id     = "your-client-id"
  client_secret = "your-client-secret"
}

resource "jamfprotect_analytic" "suspicious_process" {
  name        = "Detect Suspicious Process"
  input_type  = "event"
  description = "Detect execution of suspicious binaries."
  filter      = "process.name == 'malware'"
  level       = 5
  severity    = "High"

  tags           = ["security", "threat-hunting"]
  categories     = ["execution"]
  snapshot_files = ["/usr/bin/malware"]

  analytic_actions {
    name       = "notify"
    parameters = ["channel=security"]
  }

  context {
    name  = "process_path"
    type  = "STRING"
    exprs = ["process.path"]
  }
}
