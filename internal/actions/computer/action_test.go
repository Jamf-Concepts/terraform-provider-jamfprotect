// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computeractions_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

// Invoking an action from configuration requires a resource with a
// lifecycle.action_trigger, so every test below hangs the action off a
// terraform_data resource. Actions need Terraform 1.14 or later.

// TestAccDeleteComputerAction_missingTarget verifies that omitting the required
// selector fails at plan time. Validation runs before apply, so no computer is
// touched.
func TestAccDeleteComputerAction_missingTarget(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_14_0)},
		Steps: []resource.TestStep{
			{
				Config: `
action "jamfprotect_delete_computer" "bad" {
  config {}
}

resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.jamfprotect_delete_computer.bad]
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`(?s)computer_uuids|Missing required argument`),
			},
		},
	})
}

// TestAccDeleteComputerAction_invalidUUID verifies the UUID validator rejects a
// serial number pasted into the selector at plan time, before the destructive
// call is ever made.
func TestAccDeleteComputerAction_invalidUUID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_14_0)},
		Steps: []resource.TestStep{
			{
				Config: `
action "jamfprotect_delete_computer" "bad" {
  config {
    computer_uuids = ["C02XXXXXXXXX"]
  }
}

resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.jamfprotect_delete_computer.bad]
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`Invalid UUID Format`),
			},
		},
	})
}

// TestAccDeleteComputerAction_emptySetNoop verifies that an empty computer_uuids
// set applies cleanly as a no-op, which is what makes an offboarding pipeline
// safe to re-run once the fleet has already been cleared. Touches no computer.
func TestAccDeleteComputerAction_emptySetNoop(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_14_0)},
		Steps: []resource.TestStep{
			{
				Config: `
action "jamfprotect_delete_computer" "noop" {
  config {
    computer_uuids = []
  }
}

resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.jamfprotect_delete_computer.noop]
    }
  }
}
`,
			},
		},
	})
}

// TestAccDeleteComputerAction_alreadyDeletedNoop verifies that deleting a UUID
// which does not exist in the tenant applies cleanly, warning rather than
// failing. This is the regression test for the missing-computer detection: Jamf
// Protect answers getComputer for an absent record with a GraphQL non-nullable
// error rather than ErrNotFound, so a naive not-found check reports a failure
// here. The UUID is well-formed but not a real computer, so nothing is mutated.
func TestAccDeleteComputerAction_alreadyDeletedNoop(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_14_0)},
		Steps: []resource.TestStep{
			{
				Config: `
action "jamfprotect_delete_computer" "gone" {
  config {
    computer_uuids = ["00000000-0000-4000-8000-000000000000"]
  }
}

resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.jamfprotect_delete_computer.gone]
    }
  }
}
`,
			},
		},
	})
}

// TestAccSetComputerPlanAction_invoke moves a real computer to a real plan and
// waits for the agent to check in on it. Gated on operator-supplied targets,
// because it needs an enrolled computer and a plan that exists in the tenant:
//
//	JAMFPROTECT_ACC_COMPUTER_UUID — an enrolled computer's UUID
//	JAMFPROTECT_ACC_PLAN_ID       — the plan to move it to
//
// This changes real fleet configuration: the computer is left on
// JAMFPROTECT_ACC_PLAN_ID when the test finishes, so point it at a plan that is
// safe to land on (or move it back afterwards).
func TestAccSetComputerPlanAction_invoke(t *testing.T) {
	computerUUID := strings.TrimSpace(os.Getenv("JAMFPROTECT_ACC_COMPUTER_UUID"))
	planID := strings.TrimSpace(os.Getenv("JAMFPROTECT_ACC_PLAN_ID"))
	if computerUUID == "" || planID == "" {
		t.Skip("JAMFPROTECT_ACC_COMPUTER_UUID and JAMFPROTECT_ACC_PLAN_ID not both set — set computer plan invoke test needs a live computer and plan")
	}
	t.Logf("warning: this test moves computer %s to plan %s and leaves it there", computerUUID, planID)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_14_0)},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
action "jamfprotect_set_computer_plan" "migrate" {
  config {
    computer_uuids   = [%q]
    plan_id          = %q
    wait_for_checkin = true
    timeout          = "20m"
  }
}

resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.jamfprotect_set_computer_plan.migrate]
    }
  }
}
`, computerUUID, planID),
			},
		},
	})
}

// TestAccDeleteComputerAction_invoke deletes a real computer record. Separately
// gated because it is destructive and irreversible — the record, its alert
// history and its insights data are removed:
//
//	JAMFPROTECT_ACC_DELETE_COMPUTER_UUID — a computer record that is safe to destroy
//
// A successful apply means the deleteComputer mutation was accepted. Note the
// Mac re-enrols and reappears at its next check-in unless the agent has also
// been removed. The second step re-invokes the action against the now-deleted
// record, which must warn rather than fail.
func TestAccDeleteComputerAction_invoke(t *testing.T) {
	computerUUID := strings.TrimSpace(os.Getenv("JAMFPROTECT_ACC_DELETE_COMPUTER_UUID"))
	if computerUUID == "" {
		t.Skip("JAMFPROTECT_ACC_DELETE_COMPUTER_UUID not set — delete computer invoke test permanently removes a computer record")
	}
	t.Logf("warning: this test permanently deletes the Jamf Protect record for computer %s", computerUUID)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_14_0)},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
action "jamfprotect_delete_computer" "offboard" {
  config {
    computer_uuids = [%q]
  }
}

resource "terraform_data" "trigger" {
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.jamfprotect_delete_computer.offboard]
    }
  }
}
`, computerUUID),
			},
			{
				Config: fmt.Sprintf(`
action "jamfprotect_delete_computer" "offboard" {
  config {
    computer_uuids = [%q]
  }
}

resource "terraform_data" "trigger" {
  input = "second-invocation"

  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.jamfprotect_delete_computer.offboard]
    }
  }
}
`, computerUUID),
			},
		},
	})
}
