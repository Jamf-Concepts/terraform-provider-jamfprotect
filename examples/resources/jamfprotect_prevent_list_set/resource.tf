# Example: Prevent List Set
# Prevent list sets group custom prevent lists and scope them to plans. A custom
# prevent list reaches an endpoint only when it belongs to a prevent list set
# assigned to that endpoint's plan.

resource "jamfprotect_custom_prevent_list" "trusted_teams" {
  name         = "Trusted Team IDs"
  description  = "Team IDs of vendors approved for this fleet"
  prevent_type = "Team ID"

  list_data = [
    "ABC1234567",
    "XYZ9876543",
  ]
}

resource "jamfprotect_custom_prevent_list" "blocked_hashes" {
  name         = "Blocked File Hashes"
  description  = "SHA-256 hashes of known malware samples"
  prevent_type = "File Hash"

  list_data = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  ]
}

resource "jamfprotect_prevent_list_set" "endpoint_baseline" {
  name        = "Endpoint Baseline"
  description = "Prevent lists applied to every managed Mac"

  prevent_lists = [
    jamfprotect_custom_prevent_list.trusted_teams.id,
    jamfprotect_custom_prevent_list.blocked_hashes.id,
  ]
}

# Example: Assigning a prevent list set to a plan
# Prevent list sets do nothing until a plan references them.

resource "jamfprotect_plan" "baseline" {
  name                 = "Baseline Plan"
  description          = "Plan that applies the baseline prevent lists"
  action_configuration = jamfprotect_action_configuration.example.id
  reporting_interval   = 60

  prevent_list_sets = [
    jamfprotect_prevent_list_set.endpoint_baseline.id,
  ]
}

resource "jamfprotect_action_configuration" "example" {
  name        = "Baseline Action Configuration"
  description = "Action configuration for the baseline plan"
}

# Example: A prevent list set with no members
# Valid, and ships no prevent lists. Useful as a placeholder that plans can
# reference before the lists themselves are decided.

resource "jamfprotect_prevent_list_set" "placeholder" {
  name          = "Placeholder Set"
  description   = "Reserved for future prevent lists"
  prevent_lists = []
}
