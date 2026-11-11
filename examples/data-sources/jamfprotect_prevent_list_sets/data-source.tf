data "jamfprotect_prevent_list_sets" "example" {}

# Output all prevent list sets
output "all_prevent_list_sets" {
  value = data.jamfprotect_prevent_list_sets.example.prevent_list_sets
}

# Prevent list sets that are not assigned to any plan, and therefore reach no endpoints
output "unassigned_prevent_list_sets" {
  value = [
    for set in data.jamfprotect_prevent_list_sets.example.prevent_list_sets :
    set.name if length(set.plans) == 0
  ]
}

# Map each prevent list set to the plans it is assigned to
output "prevent_list_sets_by_plan" {
  value = {
    for set in data.jamfprotect_prevent_list_sets.example.prevent_list_sets :
    set.name => [for plan in set.plans : plan.name]
  }
}
