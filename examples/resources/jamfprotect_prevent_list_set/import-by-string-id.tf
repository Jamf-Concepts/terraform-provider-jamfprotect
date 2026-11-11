# Terraform 1.5+ Import Example
# Import an existing Jamf Protect prevent list set using the import block.
#
# Tenants that had custom prevent lists before prevent list sets existed have their
# lists migrated into sets automatically by Jamf Protect. Import one if you want
# Terraform to manage it.

import {
  to = jamfprotect_prevent_list_set.imported
  id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}

resource "jamfprotect_prevent_list_set" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
