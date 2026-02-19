# List all users in Jamf Protect.
data "jamfprotect_users" "all" {}

# Output the email addresses of all users.
output "user_emails" {
  value = [for user in data.jamfprotect_users.all.users : user.email]
}
