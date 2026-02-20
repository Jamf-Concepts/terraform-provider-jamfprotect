# Retrieve all computers enrolled in Jamf Protect
data "jamfprotect_computers" "all" {}

# Output the total number of computers
output "total_computers" {
  value = length(data.jamfprotect_computers.all.computers)
}

# Output hostnames of all computers
output "computer_hostnames" {
  value = [for computer in data.jamfprotect_computers.all.computers : computer.host_name]
}

# Find computers with specific tags
locals {
  production_computers = [
    for computer in data.jamfprotect_computers.all.computers :
    computer if contains(computer.tags, "production")
  ]
}

output "production_computer_count" {
  value = length(local.production_computers)
}
