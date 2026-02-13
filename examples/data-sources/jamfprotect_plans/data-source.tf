# List all plans in Jamf Protect.
data "jamfprotect_plans" "all" {}

# Output the names of all plans.
output "plan_names" {
  value = [for plan in data.jamfprotect_plans.all.plans : plan.name]
}
