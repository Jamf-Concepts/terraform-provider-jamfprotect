# Create a group with a Read Only role assignment.
resource "jamfprotect_group" "example" {
  name     = "Example Group"
  role_ids = ["1"]
}
