# Example: Custom Prevent List with File Hash Blocking
# This example creates a prevent list using file hashes (SHA-256) to block
# known malicious files from executing.

resource "jamfprotect_custom_prevent_list" "malware_hashes" {
  name         = "Known Malware Hashes"
  description  = "SHA-256 hashes of known malware samples"
  prevent_type = "File Hash"

  list_data = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
  ]
}

# Example: Custom Prevent List with Team ID Blocking
# This example blocks executables signed by specific developer Team IDs,
# useful for blocking software from untrusted or compromised developers.

resource "jamfprotect_custom_prevent_list" "blocked_team_ids" {
  name         = "Blocked Developer Team IDs"
  description  = "Block executables signed with compromised or untrusted certificates"
  prevent_type = "Team ID"

  list_data = [
    "ABC1234567",
    "XYZ9876543",
  ]
}

# Example: Custom Prevent List with Signing ID
# This example blocks specific signing identifiers to prevent execution of
# software from known malicious sources.

resource "jamfprotect_custom_prevent_list" "blocked_signing_ids" {
  name         = "Blocked Signing IDs"
  description  = "Block executables by signing identifier"
  prevent_type = "Signing ID"

  list_data = [
    "com.malicious.app",
    "com.suspicious.tool",
  ]
}

# Example: Custom Prevent List with Code Directory Hash
# This example uses Code Directory (CD) hashes for more targeted blocking
# of specific application versions.

resource "jamfprotect_custom_prevent_list" "blocked_cd_hashes" {
  name         = "Blocked Code Directory Hashes"
  description  = "Block specific application versions by CD hash"
  prevent_type = "Code Directory Hash"

  list_data = [
    "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
    "3c557727953a8f6b4788984464fb77741b821991ca21f6df097c57a3eb3c1f87",
  ]
}
