# Manage Jamf Protect change management (enable freeze).
resource "jamfprotect_change_management" "basic" {
  enable_freeze = true
}
