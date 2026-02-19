# Terraform 1.5+ Import Example
# Import an existing Jamf Protect custom prevent list using the import block.

import {
  to = jamfprotect_data_forwarding.imported
  id = "data_forwarding_singleton"
}

resource "jamfprotect_data_forwarding" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
