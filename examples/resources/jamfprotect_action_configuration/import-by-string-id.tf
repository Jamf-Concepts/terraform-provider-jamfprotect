# Terraform 1.5+ Import Example
# Import an existing Jamf Protect action configuration using the import block.

import {
  to = jamfprotect_action_configuration.imported
  id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}

resource "jamfprotect_action_configuration" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
