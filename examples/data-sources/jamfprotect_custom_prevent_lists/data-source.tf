# List all custom prevent lists in Jamf Protect.
data "jamfprotect_custom_prevent_lists" "all" {}

# Output the names and types of all custom prevent lists.
output "prevent_list_summary" {
  value = [for pl in data.jamfprotect_custom_prevent_lists.all.custom_prevent_lists : {
    name         = pl.name
    prevent_type = pl.prevent_type
  }]
}
