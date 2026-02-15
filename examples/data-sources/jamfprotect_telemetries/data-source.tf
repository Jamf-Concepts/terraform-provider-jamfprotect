# List all v2 telemetry configurations in Jamf Protect.
data "jamfprotect_telemetries" "all" {}

# Output the names of all v2 telemetry configurations.
output "telemetry_v2_names" {
  value = [for t in data.jamfprotect_telemetries.all.telemetries : t.name]
}
