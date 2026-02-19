# Download a plan configuration profile.
data "jamfprotect_plan_configuration_profile" "example_unsigned" {
  id                                     = "123"
  sign_profile                           = false
  include_pppc_payload                   = true
  include_system_extension_payload       = true
  include_login_background_items_payload = true
  include_websocket_authorizer_key       = true
  include_root_ca_certificate            = true
  include_csr_certificate                = true
  include_bootstrap_token                = true
}

output "plan_configuration_profile" {
  value = base64decode(data.jamfprotect_plan_configuration_profile.example_unsigned.profile)
}

resource "local_file" "plan_configuration_profile" {
  content  = base64decode(data.jamfprotect_plan_configuration_profile.example_unsigned.profile)
  filename = "plan_configuration_profile.mobileconfig"
  lifecycle {
    ignore_changes = [content]
  }
}
