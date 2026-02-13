data "jamfprotect_exception_sets" "example" {}

# Output all exception sets
output "all_exception_sets" {
  value = data.jamfprotect_exception_sets.example.exception_sets
}

# Filter for custom (non-managed) exception sets
output "custom_exception_sets" {
  value = [
    for set in data.jamfprotect_exception_sets.example.exception_sets :
    set if !set.managed
  ]
}

# Find a specific exception set by name
output "my_exception_set" {
  value = [
    for set in data.jamfprotect_exception_sets.example.exception_sets :
    set if set.name == "My Custom Exceptions"
  ][0]
}
