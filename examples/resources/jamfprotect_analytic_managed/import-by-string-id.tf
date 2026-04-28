# Terraform 1.5+ Import Example
# Import an existing Jamf Protect managed analytic using the import block.
# The analytic UUID can be found in the Jamf Protect web console or via the API.

import {
  to = jamfprotect_analytic_managed.imported_jamf_analytic
  id = "abcd1234-5678-90ef-ghij-klmnopqrstuv" # Replace with the actual UUID of the managed analytic
}

resource "jamfprotect_analytic_managed" "imported_jamf_analytic" {
  # Configuration will be populated during import
  # After successful import, run 'terraform plan' to see the current state
  # Then update this block with the actual configuration values
}
