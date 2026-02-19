# List all groups in Jamf Protect.
data "jamfprotect_groups" "all" {}

# Output the group names.
output "group_names" {
  value = [for group in data.jamfprotect_groups.all.groups : group.name]
}
