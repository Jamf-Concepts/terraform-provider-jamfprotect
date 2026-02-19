# Terraform 1.5+ Import Example
# Import an existing Jamf Protect data retention settings using the import block.

import {
  to = jamfprotect_data_retention.imported
  id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}

resource "jamfprotect_data_retention" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
