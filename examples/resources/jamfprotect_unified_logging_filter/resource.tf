provider "jamfprotect" {
  url           = "https://your-tenant.protect.jamfcloud.com"
  client_id     = "your-client-id"
  client_secret = "your-client-secret"
}

resource "jamfprotect_unified_logging_filter" "auth_failures" {
  name        = "Authentication Failures"
  description = "Collect authentication failure log entries."
  filter      = "eventMessage CONTAINS 'Authentication failed'"
  level       = "DEFAULT"
  enabled     = true
  tags        = ["logging", "auth"]
}
