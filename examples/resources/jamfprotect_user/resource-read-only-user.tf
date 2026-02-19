# Create a Jamf Protect user, read-only, default group.
resource "jamfprotect_user" "read_only" {
  email                    = "someone@example.com"
  identity_provider_id     = "1"
  role_ids                 = ["1"]
  group_ids                = []
  send_email_notifications = true
  email_severity           = "Medium"
}
