# Example: Custom Prevent List with Hash-based Blocking
# This example creates a prevent list using file hashes to block known malicious files.

resource "jamfprotect_custom_prevent_list" "malware_hashes" {
  name        = "Known Malware Hashes"
  description = "SHA-256 hashes of known malware samples"

  prevent_list_hash = [
    {
      hash        = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      description = "Malware Sample A"
    },
    {
      hash        = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
      description = "Ransomware Sample B"
    },
    {
      hash        = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
      description = "Trojan Sample C"
    },
  ]
}
