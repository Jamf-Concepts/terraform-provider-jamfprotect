# List all prevent lists in Jamf Protect.
data "jamfprotect_prevent_lists" "all" {}

# Output the names and types of all prevent lists.
output "prevent_list_summary" {
  value = [for pl in data.jamfprotect_prevent_lists.all.prevent_lists : {
    name = pl.name
    type = pl.type
  }]
}
