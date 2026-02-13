data "jamfprotect_analytic_sets" "example" {}

# Output all analytic sets
output "all_analytic_sets" {
  value = data.jamfprotect_analytic_sets.example.analytic_sets
}

# Filter for custom (non-managed) analytic sets
output "custom_analytic_sets" {
  value = [
    for set in data.jamfprotect_analytic_sets.example.analytic_sets :
    set if !set.managed
  ]
}

# Find a specific analytic set by name
output "my_analytic_set" {
  value = [
    for set in data.jamfprotect_analytic_sets.example.analytic_sets :
    set if set.name == "My Custom Set"
  ][0]
}
