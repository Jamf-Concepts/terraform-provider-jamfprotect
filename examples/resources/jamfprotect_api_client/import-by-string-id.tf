# Terraform 1.5+ Import Example
# Import an existing Jamf Protect API client using the import block.

import {
  to = jamfprotect_api_client.imported
  id = "123"
}

resource "jamfprotect_api_client" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
