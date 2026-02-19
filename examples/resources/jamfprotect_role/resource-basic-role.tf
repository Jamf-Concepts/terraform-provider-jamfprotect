# Create a role with read and write access to analytics.
resource "jamfprotect_role" "basic" {
  name              = "tf-basic-role"
  read_permissions  = ["Analytics"]
  write_permissions = ["Analytics"]
}
