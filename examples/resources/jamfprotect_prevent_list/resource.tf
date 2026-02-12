provider "jamfprotect" {
  url           = "https://your-tenant.protect.jamfcloud.com"
  client_id     = "your-client-id"
  client_secret = "your-client-secret"
}

resource "jamfprotect_prevent_list" "blocked_team_ids" {
  name        = "Blocked Team IDs"
  description = "Block known malicious Team IDs."
  type        = "TEAMID"
  tags        = ["threat-prevention", "block"]
  list        = ["ABCDE12345", "FGHIJ67890"]
}
