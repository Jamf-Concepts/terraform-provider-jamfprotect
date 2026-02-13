# List all v2 telemetry configurations in Jamf Protect.
data "jamfprotect_telemetries_v2" "all" {}

# Output the names of all v2 telemetry configurations.
output "telemetry_v2_names" {
  value = [for t in data.jamfprotect_telemetries_v2.all.telemetries_v2 : t.name]
}
