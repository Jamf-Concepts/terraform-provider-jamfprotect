data "jamfprotect_unified_logging_filter_sets" "example" {}

# Output all unified logging filter sets
output "all_unified_logging_filter_sets" {
  value = data.jamfprotect_unified_logging_filter_sets.example.unified_logging_filter_sets
}

# Find the "Default" set that Jamf Protect creates for tenants which had unified
# logging filters enabled before filter sets existed
output "default_filter_set" {
  value = [
    for set in data.jamfprotect_unified_logging_filter_sets.example.unified_logging_filter_sets :
    set if set.name == "Default"
  ]
}

# Filter sets that are not assigned to any plan, and therefore ship nothing
output "unassigned_filter_sets" {
  value = [
    for set in data.jamfprotect_unified_logging_filter_sets.example.unified_logging_filter_sets :
    set.name if length(set.plans) == 0
  ]
}

# Map each filter set to the plans it is assigned to
output "filter_sets_by_plan" {
  value = {
    for set in data.jamfprotect_unified_logging_filter_sets.example.unified_logging_filter_sets :
    set.name => [for plan in set.plans : plan.name]
  }
}
