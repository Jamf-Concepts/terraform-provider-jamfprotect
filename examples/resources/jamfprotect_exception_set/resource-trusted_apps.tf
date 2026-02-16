# Example: Exception Set for Trusted Applications
# This example creates exceptions for known-good applications to reduce false positives
# from legitimate enterprise software.

resource "jamfprotect_exception_set" "trusted_apps" {
  name        = "Trusted Enterprise Applications"
  description = "Exceptions for approved enterprise software"

  # Exception for Apple platform binaries
  exception {
    type            = "PlatformBinary"
    value           = "com.apple.Safari"
    analytic_types  = ["GPProcessEvent", "GPFSEvent"]
    ignore_activity = "Analytics"
  }

  # Exception for trusted developer Team ID
  exception {
    type            = "TeamId"
    value           = "9JA89QQLNQ" # Adobe Team ID
    analytic_types  = ["GPProcessEvent"]
    ignore_activity = "Analytics"
  }

  # Exception for specific user telemetry
  exception {
    type            = "User"
    value           = "_spotlight"
    ignore_activity = "Telemetry"
  }

  # Exception for system group
  exception {
    type            = "Groups"
    value           = "wheel"
    analytic_types  = ["GPProcessEvent"]
    ignore_activity = "Analytics"
  }
}
