resource "jamfprotect_custom_prevent_list" "example" {
  description  = "Managed by Terraform"
  list_data    = ["EXAMPLE"]
  name         = "Example"
  prevent_type = "Team ID"
}
