# List all removable storage control sets in Jamf Protect.
data "jamfprotect_removable_storage_control_sets" "all" {}

# Output the names and default permissions of all removable storage control sets.
output "removable_storage_control_set_summary" {
  value = [for s in data.jamfprotect_removable_storage_control_sets.all.removable_storage_control_sets : {
    name               = s.name
    default_permission = s.default_permission
  }]
}
