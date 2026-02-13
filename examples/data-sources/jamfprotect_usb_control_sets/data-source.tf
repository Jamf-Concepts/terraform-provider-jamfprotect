# List all USB control sets in Jamf Protect.
data "jamfprotect_usb_control_sets" "all" {}

# Output the names and default mount actions of all USB control sets.
output "usb_control_set_summary" {
  value = [for u in data.jamfprotect_usb_control_sets.all.usb_control_sets : {
    name                 = u.name
    default_mount_action = u.default_mount_action
  }]
}
