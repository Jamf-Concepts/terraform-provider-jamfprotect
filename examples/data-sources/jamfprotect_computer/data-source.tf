# Retrieve a single computer by UUID
data "jamfprotect_computer" "example" {
  uuid = "12345678-1234-1234-1234-123456789012"
}

# Output computer details
output "computer_hostname" {
  value = data.jamfprotect_computer.example.host_name
}

output "computer_os_version" {
  value = "${data.jamfprotect_computer.example.os_major}.${data.jamfprotect_computer.example.os_minor}.${data.jamfprotect_computer.example.os_patch}"
}

output "computer_plan" {
  value = data.jamfprotect_computer.example.plan.name
}
