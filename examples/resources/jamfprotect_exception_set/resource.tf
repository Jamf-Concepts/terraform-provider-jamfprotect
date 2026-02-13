resource "jamfprotect_exception_set" "example" {
  name        = "Development Exceptions"
  description = "Exceptions for development environment tools"

  # Standard exceptions with app signing info
  exceptions = [
    {
      type            = "SHA256Hash"
      value           = "abc123def456..."
      ignore_activity = false
      analytic_types  = ["Report", "Prevent"]
      app_signing_info = {
        app_id  = "com.example.devtool"
        team_id = "ABC123XYZ"
      }
    },
    {
      type             = "ProcessPath"
      value            = "/usr/local/bin/development-tool"
      ignore_activity  = true
      analytic_types   = ["Report"]
      app_signing_info = null
    }
  ]

  # ES (Endpoint Security) exceptions
  es_exceptions = [
    {
      type                = "ProcessPath"
      value               = "/Applications/Xcode.app/Contents/MacOS/Xcode"
      ignore_activity     = false
      ignore_list_type    = "ALLOW"
      ignore_list_subtype = "NONE"
      event_type          = "ES_EVENT_TYPE_AUTH_EXEC"
      app_signing_info = {
        app_id  = "com.apple.dt.Xcode"
        team_id = "59GAB85EFG"
      }
    }
  ]

  timeouts {
    create = "5m"
    update = "5m"
    delete = "2m"
  }
}

# Simple exception set with minimal configuration
resource "jamfprotect_exception_set" "simple" {
  name = "Simple Exception Set"

  exceptions = [
    {
      type            = "TeamID"
      value           = "ABC123XYZ"
      ignore_activity = false
      analytic_types  = ["Report"]
    }
  ]

  # es_exceptions is optional and can be omitted
}
