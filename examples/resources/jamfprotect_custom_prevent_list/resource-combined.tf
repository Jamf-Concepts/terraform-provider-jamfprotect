# Example: Combined Custom Prevent List
# This example demonstrates using both hash-based and certificate-based prevention
# in a single prevent list for comprehensive malware blocking.

resource "jamfprotect_custom_prevent_list" "comprehensive_blocking" {
  name        = "Comprehensive Malware Prevention"
  description = "Combined hash and certificate-based malware blocking"

  # Block specific malicious file hashes
  prevent_list_hash = [
    {
      hash        = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
      description = "WannaCry Ransomware Sample"
    },
    {
      hash        = "3c557727953a8f6b4788984464fb77741b821991ca21f6df097c57a3eb3c1f87"
      description = "NotPetya Malware Sample"
    },
  ]

  # Block certificates from known malicious actors
  prevent_list_certificate = [
    {
      team_id     = "MALWARE01"
      description = "Known Malware Distribution Certificate"
    },
  ]
}
