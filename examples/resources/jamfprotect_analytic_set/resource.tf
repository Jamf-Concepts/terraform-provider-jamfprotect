resource "jamfprotect_analytic_set" "example" {
  analytics = [
    "3c8a88ef-277a-4238-a695-ebaa6eee0921",
    "dcb69719-5ae1-46f6-972a-da1799daa00c",
  ]
  description = "Managed by Terraform"
  name        = "Example Analytic Set"
}
