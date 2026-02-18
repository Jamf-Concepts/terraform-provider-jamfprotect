resource "jamfprotect_exception_set" "example" {
  description = "Managed by Terraform"
  name        = "Example Exception Set"
  endpoint_security_exception {
    ignore_activity  = "ThreatPrevention"
    ignore_list_type = "ignore"
    type             = "Group"
    value            = "EXAMPLE"
  }
  endpoint_security_exception {
    ignore_activity     = "ThreatPrevention"
    ignore_list_subtype = "parent"
    ignore_list_type    = "ignore"
    type                = "User"
    value               = "Example"
  }
  endpoint_security_exception {
    app_id              = "Example"
    ignore_activity     = "ThreatPrevention"
    ignore_list_subtype = "responsible"
    ignore_list_type    = "ignore"
    team_id             = "EXAMPLE"
    type                = "App Signing Info"
  }
  exception {
    analytic_types  = ["GPFSEvent"]
    ignore_activity = "Analytics"
    type            = "Platform Binary"
    value           = "com.apple.SafariBookmarksSyncAgent"
  }
  exception {
    ignore_activity = "Telemetry"
    type            = "User"
    value           = "_spotlight"
  }
  exception {
    analytic_types  = ["GPProcessEvent"]
    ignore_activity = "Analytics"
    type            = "Team ID"
    value           = "PXPZ95SK77"
  }
}
