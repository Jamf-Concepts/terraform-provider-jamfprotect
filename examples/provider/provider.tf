provider "jamfprotect" {
  # Prefer environment variables for credentials:
  # JAMFPROTECT_URL, JAMFPROTECT_CLIENT_ID, JAMFPROTECT_CLIENT_SECRET
  url           = "https://your-tenant.protect.jamfcloud.com"
  client_id     = "your-client-id"
  client_secret = "your-client-secret"
}
