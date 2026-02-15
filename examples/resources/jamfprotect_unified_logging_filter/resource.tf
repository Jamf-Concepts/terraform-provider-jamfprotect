resource "jamfprotect_unified_logging_filter" "example" {
  description = "Managed by Terraform"
  enabled     = true
  filter      = "eventMessage CONTAINS 'Example'"
  name        = "Example Filter"
  tags        = ["example_1", "example_2"]
}
