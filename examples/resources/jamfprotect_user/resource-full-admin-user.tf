# Create a Jamf Protect user, full admin, default group.
resource "jamfprotect_user" "full_admin" {
  email                    = "someone@example.com"
  identity_provider_id     = "1"
  role_ids                 = ["2"]
  group_ids                = ["1"]
  send_email_notifications = true
  email_severity           = "Medium"
}
