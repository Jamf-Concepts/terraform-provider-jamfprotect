# Terraform 1.5+ Import Example
# Import an existing Jamf Protect user using the import block.

import {
  to = jamfprotect_user.imported
  id = "123"
}

resource "jamfprotect_user" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
