# List all identity provider connections in Jamf Protect.
data "jamfprotect_identity_providers" "all" {}

# Output the identity provider names.
output "identity_provider_names" {
  value = [for idp in data.jamfprotect_identity_providers.all.identity_providers : idp.name]
}
