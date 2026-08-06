# Terraform 1.5+ Import Example
# Import an existing Jamf Protect unified logging filter set using the import block.
#
# Tenants that had unified logging filters enabled before filter sets existed have
# a set named "Default" created automatically by Jamf Protect. Import it if you
# want Terraform to manage it.

import {
  to = jamfprotect_unified_logging_filter_set.imported
  id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}

resource "jamfprotect_unified_logging_filter_set" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
