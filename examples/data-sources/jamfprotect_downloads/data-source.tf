# Retrieve Jamf Protect download payloads.
data "jamfprotect_downloads" "current" {}

# Output the Jamf Protect installer package URL.
output "jamfprotect_installer_package_url" {
  value     = data.jamfprotect_downloads.current.installer_package_url
  sensitive = true
}

# Save the non-removable system extension profile to a local file.
resource "local_file" "non_removable_system_extension_profile" {
  content  = base64decode(data.jamfprotect_downloads.current.non_removable_system_extension_profile)
  filename = "non_removable_system_extension_profile.mobileconfig"
}
