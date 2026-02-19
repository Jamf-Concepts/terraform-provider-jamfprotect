# Create a user that only receives email notifications.
resource "jamfprotect_user" "email_only" {
  provider                 = jamfprotect
  email                    = "testuser@email.com"
  email_severity           = "Medium"
  send_email_notifications = true
}
