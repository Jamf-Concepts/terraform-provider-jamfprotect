# Terraform 1.5+ Import Example
# Import an existing Jamf Protect analytic using the import block.
# The analytic UUID can be found in the Jamf Protect web console or via the API.

import {
  to = jamfprotect_analytic.imported_analytic
  id = "3c8a88ef-277a-4238-a695-ebaa6eee0921"
}

resource "jamfprotect_analytic" "imported_analytic" {
  # Configuration will be populated during import
  # After successful import, run 'terraform plan' to see the current state
  # Then update this block with the actual configuration values
}
