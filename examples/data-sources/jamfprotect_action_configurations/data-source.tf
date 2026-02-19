# List all action configurations in Jamf Protect.
# Note: only basic fields (id, name, description, created, updated) are
# returned by the list API. Use the jamfprotect_action_configuration resource
# to read full details including alert_data_collection and endpoint blocks.
data "jamfprotect_action_configurations" "all" {}

# Output the names of all action configurations.
output "action_config_names" {
  value = [for ac in data.jamfprotect_action_configurations.all.action_configs : ac.name]
}
