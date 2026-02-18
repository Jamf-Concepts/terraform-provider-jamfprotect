resource "jamfprotect_exception_set" "example" {
  description = "Managed by Terraform"
  name        = "Example Exception Set"
  exceptions = [
    {
      type     = "Override Endpoint Threat Prevention"
      sub_type = "Process"
      rules = [
        {
          rule_type = "Group"
          value     = "EXAMPLE"
        },
      ]
    },
    {
      type = "File System Event"
      rules = [
        {
          rule_type = "File Path"
          value     = "/Library/Logs/example.log"
        },
      ]
    },
    {
      type     = "Ignore for Telemetry"
      sub_type = "Exec Process"
      rules = [
        {
          rule_type = "Process Path"
          value     = "/usr/bin/test"
        },
      ]
    },
    {
      type = "Ignore for Telemetry (Deprecated)"
      rules = [
        {
          rule_type = "User"
          value     = "_spotlight"
        },
      ]
    },
  ]
}
