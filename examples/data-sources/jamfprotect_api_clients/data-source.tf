# List all API clients in Jamf Protect.
data "jamfprotect_api_clients" "all" {}

# Output the API client names.
output "api_client_names" {
  value = [for client in data.jamfprotect_api_clients.all.api_clients : client.name]
}
