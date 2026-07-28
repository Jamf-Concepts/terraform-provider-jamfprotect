# Move computers to a different Jamf Protect plan.
#
# Computers are selected from the jamfprotect_computers data source, which
# exposes uuid, serial, host_name, tags, connection_status, checkin and the
# nested plan object (id, name, hash).
data "jamfprotect_computers" "all" {}

data "jamfprotect_plans" "all" {}

locals {
  # In a real configuration this is usually a managed plan — for example
  # jamfprotect_plan.managed_protect_enhanced.id.
  target_plan_id = one([
    for p in data.jamfprotect_plans.all.plans : p.id
    if p.name == "Managed Protect - Enhanced"
  ])
}

# Mode 1 — move a single computer.
action "jamfprotect_set_computer_plan" "one" {
  config {
    computer_uuids = ["12345678-1234-1234-1234-123456789012"]
    plan_id        = local.target_plan_id
  }
}

# Mode 2 — move every computer currently on one plan to another in a single
# invocation, waiting for each agent to check in before the action completes.
# The wait matters when a later operation depends on the move having landed:
# Jamf Protect refuses to delete a plan while computers are still assigned to it.
action "jamfprotect_set_computer_plan" "migrate" {
  config {
    computer_uuids = [
      for c in data.jamfprotect_computers.all.computers :
      c.uuid if c.plan.name == "Managed Protect - Threat Prevention"
    ]
    plan_id          = local.target_plan_id
    wait_for_checkin = true
    timeout          = "30m"
  }
}

# Mode 3 — per-computer fan-out with for_each, for granular targeting and
# per-instance invocation.
action "jamfprotect_set_computer_plan" "per_computer" {
  for_each = {
    for c in data.jamfprotect_computers.all.computers :
    c.uuid => c if contains(c.tags, "pilot")
  }

  config {
    computer_uuids = [each.value.uuid]
    plan_id        = local.target_plan_id
  }
}

# Terraform 1.14 has no destroy-time action events, so the primary workflow is
# direct invocation:
#
#   terraform apply -invoke=action.jamfprotect_set_computer_plan.migrate
#
# A for_each'd action is addressed per instance:
#
#   terraform apply -invoke='action.jamfprotect_set_computer_plan.per_computer["12345678-1234-1234-1234-123456789012"]'

# Secondary pattern — run the migration from a resource lifecycle event instead
# of invoking it by hand.
resource "terraform_data" "migrate_on_create" {
  input = local.target_plan_id

  lifecycle {
    action_trigger {
      events  = [after_create, after_update]
      actions = [action.jamfprotect_set_computer_plan.migrate]
    }
  }
}
