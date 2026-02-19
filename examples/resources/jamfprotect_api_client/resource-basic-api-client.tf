# Create an API client with a Read Only role.
resource "jamfprotect_api_client" "basic" {
  name     = "tf-api-client"
  role_ids = ["1"]
}
