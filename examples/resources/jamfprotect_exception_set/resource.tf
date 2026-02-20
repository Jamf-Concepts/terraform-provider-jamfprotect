# Example: Exception Set for Process Event Analytics
# This example shows exceptions for process event analytics to reduce false positives
# from legitimate enterprise software.

resource "jamfprotect_exception_set" "trusted_apps" {
  name        = "Trusted Enterprise Applications"
  description = "Exceptions for approved enterprise software"

  exceptions = [
    {
      type = "Process Event"
      rules = [
        {
          rule_type = "Platform Binary"
          value     = "com.apple.Safari"
        },
        {
          rule_type = "Team ID"
          value     = "9JA89QQLNQ" # Adobe
        },
      ]
    },
    {
      type = "File System Event"
      rules = [
        {
          rule_type = "Process Path"
          value     = "/usr/local/bin/homebrew"
        },
      ]
    },
  ]
}

# Example: Exception Set with App Signing Info
# This example creates exceptions using app signing information for
# more precise application matching.

resource "jamfprotect_exception_set" "app_signing_exceptions" {
  name        = "App Signing Info Exceptions"
  description = "Exceptions based on app signing information"

  exceptions = [
    {
      type = "Process Event"
      rules = [
        {
          rule_type = "App Signing Info"
          app_id    = "com.microsoft.teams"
          team_id   = "UBF8T346G9"
        },
        {
          rule_type = "App Signing Info"
          app_id    = "com.apple.dt.Xcode"
          team_id   = "59GAB85EFG"
        },
      ]
    },
  ]
}

# Example: Exception Set for Endpoint Threat Prevention
# This example shows how to override endpoint threat prevention controls
# for specific trusted processes.

resource "jamfprotect_exception_set" "endpoint_security_overrides" {
  name        = "Endpoint Security Overrides"
  description = "Override threat prevention for trusted security tools"

  exceptions = [
    {
      type     = "Override Endpoint Threat Prevention"
      sub_type = "Process"
      rules = [
        {
          rule_type = "App Signing Info"
          app_id    = "com.crowdstrike.falcon"
          team_id   = "X9E956P446"
        },
      ]
    },
    {
      type     = "Ignore for Telemetry"
      sub_type = "Source Parent Process"
      rules = [
        {
          rule_type = "Process Path"
          value     = "/usr/bin/mdworker_shared"
        },
      ]
    },
  ]
}
