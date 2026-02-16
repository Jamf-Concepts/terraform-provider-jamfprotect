# Example: Exception Set for Endpoint Security
# This example shows endpoint security exceptions for threat prevention features,
# useful for excluding trusted processes from security controls.

resource "jamfprotect_exception_set" "endpoint_security_exceptions" {
  name        = "Endpoint Security Exceptions"
  description = "Exclusions for endpoint threat prevention"

  # Exclude trusted application by signing info
  endpoint_security_exception {
    type                = "AppSigningInfo"
    app_id              = "com.microsoft.teams"
    team_id             = "UBF8T346G9"
    ignore_activity     = "ThreatPrevention"
    ignore_list_type    = "ignore"
    ignore_list_subtype = "responsible"
  }

  # Exclude specific user from threat prevention
  endpoint_security_exception {
    type                = "User"
    value               = "admin"
    ignore_activity     = "ThreatPrevention"
    ignore_list_type    = "ignore"
    ignore_list_subtype = "parent"
  }

  # Exclude group from advanced threat controls
  endpoint_security_exception {
    type             = "Groups"
    value            = "Developers"
    ignore_activity  = "ThreatPrevention"
    ignore_list_type = "ignore"
  }

  # Also include some analytic exceptions
  exception {
    type            = "PlatformBinary"
    value           = "com.apple.dt.Xcode"
    analytic_types  = ["GPProcessEvent", "GPFSEvent"]
    ignore_activity = "Analytics"
  }
}
