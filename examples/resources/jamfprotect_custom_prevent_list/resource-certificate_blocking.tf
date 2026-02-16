# Example: Custom Prevent List with Certificate Blocking
# This example blocks executables signed with specific certificates,
# useful for blocking software from untrusted or compromised developers.

resource "jamfprotect_custom_prevent_list" "blocked_certificates" {
  name        = "Blocked Developer Certificates"
  description = "Block executables signed with compromised or untrusted certificates"

  prevent_list_certificate = [
    {
      team_id     = "ABC1234567"
      description = "Revoked Developer Certificate - Compromised"
    },
    {
      team_id     = "XYZ9876543"
      description = "Untrusted Third-Party Developer"
    },
  ]
}
