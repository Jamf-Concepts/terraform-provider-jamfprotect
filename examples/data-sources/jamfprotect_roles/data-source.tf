# List all roles in Jamf Protect.
data "jamfprotect_roles" "all" {}

# Output the role names.
output "role_names" {
  value = [for role in data.jamfprotect_roles.all.roles : role.name]
}
