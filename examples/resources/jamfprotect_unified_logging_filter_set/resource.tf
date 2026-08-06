# Example: Unified Logging Filter Set
# Filter sets group unified logging filters and scope them to plans. A filter
# reaches an endpoint only when it belongs to a filter set assigned to that
# endpoint's plan.

resource "jamfprotect_unified_logging_filter" "time_machine" {
  name        = "Time Machine Activity"
  description = "Captures Time Machine backup activity"
  filter      = "subsystem == \"com.apple.TimeMachine\""
  tags        = ["backup"]
}

resource "jamfprotect_unified_logging_filter" "screen_sharing" {
  name        = "Screen Sharing Sessions"
  description = "Captures screen sharing connections"
  filter      = "subsystem == \"com.apple.screensharing\""
  tags        = ["remote-access"]
}

resource "jamfprotect_unified_logging_filter_set" "endpoint_diagnostics" {
  name        = "Endpoint Diagnostics"
  description = "Diagnostic log capture for troubleshooting fleets"

  filters = [
    jamfprotect_unified_logging_filter.time_machine.id,
    jamfprotect_unified_logging_filter.screen_sharing.id,
  ]
}

# Example: Assigning a filter set to a plan
# Filter sets do nothing until a plan references them.

resource "jamfprotect_plan" "diagnostics" {
  name                 = "Diagnostics Plan"
  description          = "Plan with diagnostic unified logging enabled"
  action_configuration = jamfprotect_action_configuration.example.id
  reporting_interval   = 60

  unified_logging_filter_sets = [
    jamfprotect_unified_logging_filter_set.endpoint_diagnostics.id,
  ]
}

resource "jamfprotect_action_configuration" "example" {
  name        = "Diagnostics Action Configuration"
  description = "Action configuration for the diagnostics plan"
}

# Example: A filter set with no members
# Valid, and ships no filters. Useful as a placeholder that plans can reference
# before the filters themselves are decided.

resource "jamfprotect_unified_logging_filter_set" "placeholder" {
  name        = "Placeholder Set"
  description = "Reserved for future filters"
  filters     = []
}
