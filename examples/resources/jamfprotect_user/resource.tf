# Create a Jamf Protect user, read-only, default group.
resource "jamfprotect_user" "read_only" {
  email                    = "someone@example.com"
  identity_provider_id     = "1"
  role_ids                 = ["1"]
  group_ids                = []
  send_email_notifications = true
  email_severity           = "Medium"
}

# Create a user that only receives email notifications.
resource "jamfprotect_user" "email_only" {
  provider                 = jamfprotect
  email                    = "testuser@email.com"
  email_severity           = "Medium"
  send_email_notifications = true
}

# Create a Jamf Protect user, full admin, default group.
resource "jamfprotect_user" "full_admin" {
  email                    = "someone@example.com"
  identity_provider_id     = "1"
  role_ids                 = ["2"]
  group_ids                = ["1"]
  send_email_notifications = true
  email_severity           = "Medium"
}
