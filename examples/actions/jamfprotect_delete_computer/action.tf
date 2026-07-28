# Remove computer records from the Jamf Protect tenant.
#
# This is destructive and irreversible: the record, its alert history and its
# insights data are removed. It does not uninstall the Jamf Protect agent, so
# unless the endpoint has also been unenrolled on the Jamf Pro side, the Mac
# re-enrols and reappears at its next check-in.
data "jamfprotect_computers" "all" {}

data "jamfprotect_plans" "all" {}

locals {
  # The plan being retired. In a real configuration this is usually a managed
  # plan — for example jamfprotect_plan.managed_protect_standard.id.
  retiring_plan_id = one([
    for p in data.jamfprotect_plans.all.plans : p.id
    if p.name == "Managed Protect - Standard"
  ])
}

# Mode 1 — delete a single computer record.
action "jamfprotect_delete_computer" "one" {
  config {
    computer_uuids = ["12345678-1234-1234-1234-123456789012"]
  }
}

# Mode 2 — clear every computer off the plan being retired, in one invocation.
#
# This is the offboarding case: Jamf Protect blocks `deletePlan` while computers
# are still assigned, and Terraform destroys jamfprotect_plan first because the
# plan is the dependent in the graph. Run this before terraform destroy:
#
#   terraform apply -invoke=action.jamfprotect_delete_computer.offboard
#   terraform destroy
#
# An empty set is a no-op, so re-running a cleared pipeline is safe.
action "jamfprotect_delete_computer" "offboard" {
  config {
    computer_uuids = [
      for c in data.jamfprotect_computers.all.computers :
      c.uuid if c.plan.id == local.retiring_plan_id
    ]
  }
}

# Mode 3 — delete stale records only: computers that have been disconnected
# since before a cut-off date.
action "jamfprotect_delete_computer" "stale" {
  config {
    computer_uuids = [
      for c in data.jamfprotect_computers.all.computers :
      c.uuid if c.connection_status == "Disconnected" && c.checkin < "2026-01-01T00:00:00Z"
    ]
  }
}

# Mode 4 — per-computer fan-out, addressed per instance at invoke time:
#
#   terraform apply -invoke='action.jamfprotect_delete_computer.per_computer["12345678-1234-1234-1234-123456789012"]'
action "jamfprotect_delete_computer" "per_computer" {
  for_each = {
    for c in data.jamfprotect_computers.all.computers :
    c.uuid => c if contains(c.tags, "decommissioned")
  }

  config {
    computer_uuids = [each.value.uuid]
  }
}
