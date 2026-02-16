# Terraform 1.5+ Import Example
# Import an existing Jamf Protect plan using the import block.

import {
  to = jamfprotect_plan.imported
  id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}

resource "jamfprotect_plan" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
