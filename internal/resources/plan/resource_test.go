// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func testAccPlanCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_plan" {
			continue
		}
		result, err := c.GetPlan(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("plan %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccPlanResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-plan")
	resourceName := "jamfprotect_plan.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccPlanCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccPlanResourceConfig(rName, "Test plan description"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test plan description"),
					resource.TestCheckResourceAttr(resourceName, "auto_update", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
				),
			},
			// ImportState testing.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing.
			{
				Config: testAccPlanResourceConfig(rName, "Updated plan description"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated plan description"),
				),
			},
		},
	})
}

// testAccPlanResourceConfig creates a plan that depends on an action config.
// The action config is created inline to provide a valid action_configuration ID.
func testAccPlanResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_configuration" "test" {
  name        = "%[1]s-ac"
  description = "Action config for plan test"

  alert_data_collection = {
    binary_included_data_attributes                     = []
    synthetic_click_event_included_data_attributes      = []
    download_event_included_data_attributes             = []
    file_included_data_attributes                       = []
    file_system_event_included_data_attributes          = []
    group_included_data_attributes                      = []
    process_event_included_data_attributes              = []
    process_included_data_attributes                    = []
    screenshot_event_included_data_attributes           = []
    user_included_data_attributes                       = []
    gatekeeper_event_included_data_attributes           = []
    keylog_register_event_included_data_attributes      = []
  }
}

resource "jamfprotect_plan" "test" {
	name                  = %[1]q
	description           = %[2]q
	action_configuration  = jamfprotect_action_configuration.test.id
	communications_protocol = "MQTT:443"
	reporting_interval    = 1440
	report_architecture   = true
	report_os_version     = true

	endpoint_threat_prevention = "Block and report"
}
`, name, description)
}

// TestAccPlanResource_omittedSetsKeepOutOfBandMembership checks that a configuration
// omitting exception_sets and analytic_sets keeps sets attached outside Terraform when
// an unrelated attribute changes, with advanced threat controls and tamper prevention
// enabled so the analytic set list is rebuilt on update.
func TestAccPlanResource_omittedSetsKeepOutOfBandMembership(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-plan-oob")
	planResourceName := "jamfprotect_plan.test"
	exceptionSetResourceName := "jamfprotect_exception_set.test"
	analyticSetResourceName := "jamfprotect_analytic_set.test"

	var planID, exceptionSetUUID, analyticSetUUID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccPlanCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPlanOmittedSetsConfig(rName, "Before out-of-band change"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testutil.CaptureAttr(planResourceName, "id", &planID),
					testutil.CaptureAttr(exceptionSetResourceName, "id", &exceptionSetUUID),
					testutil.CaptureAttr(analyticSetResourceName, "id", &analyticSetUUID),
				),
			},
			{
				PreConfig: func() {
					if err := testAccPlanAttachSetsOutOfBand(planID, exceptionSetUUID, analyticSetUUID); err != nil {
						t.Fatalf("failed to attach sets out of band: %v", err)
					}
				},
				Config: testAccPlanOmittedSetsConfig(rName, "After out-of-band change"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "description", "After out-of-band change"),
					resource.TestCheckTypeSetElemAttrPair(planResourceName, "exception_sets.*", exceptionSetResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(planResourceName, "analytic_sets.*", analyticSetResourceName, "id"),
					resource.TestCheckResourceAttr(planResourceName, "advanced_threat_controls", "Block and report"),
					resource.TestCheckResourceAttr(planResourceName, "tamper_prevention", "Block and report"),
					func(*terraform.State) error {
						return testAccPlanHasSets(planID, exceptionSetUUID, analyticSetUUID)
					},
				),
			},
		},
	})
}

// testAccPlanAttachSetsOutOfBand adds an exception set and a custom analytic set to a
// plan through the API, keeping its current membership, as an edit in the Jamf Protect
// console would.
func testAccPlanAttachSetsOutOfBand(planID, exceptionSetUUID, analyticSetUUID string) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	ctx := context.Background()

	api, err := c.GetPlan(ctx, planID)
	if err != nil {
		return fmt.Errorf("GetPlan(%s): %w", planID, err)
	}
	if api == nil {
		return fmt.Errorf("plan %s not found", planID)
	}

	input := testutil.PlanUpdateInput(*api)
	input.ExceptionSets = []string{exceptionSetUUID}
	for _, es := range api.ExceptionSets {
		input.ExceptionSets = append(input.ExceptionSets, es.UUID)
	}
	input.AnalyticSets = []jamfprotect.PlanAnalyticSetInput{{Type: "Report", UUID: analyticSetUUID}}
	for _, as := range api.AnalyticSets {
		input.AnalyticSets = append(input.AnalyticSets, jamfprotect.PlanAnalyticSetInput{Type: as.Type, UUID: as.AnalyticSet.UUID})
	}

	if _, err := c.UpdatePlan(ctx, planID, input); err != nil {
		return fmt.Errorf("UpdatePlan(%s): %w", planID, err)
	}
	return testAccPlanHasSets(planID, exceptionSetUUID, analyticSetUUID)
}

// testAccPlanHasSets reads the plan from the API and checks that the exception set and
// the custom analytic set are both attached.
func testAccPlanHasSets(planID, exceptionSetUUID, analyticSetUUID string) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	api, err := c.GetPlan(context.Background(), planID)
	if err != nil {
		return fmt.Errorf("GetPlan(%s): %w", planID, err)
	}
	if api == nil {
		return fmt.Errorf("plan %s not found", planID)
	}

	hasExceptionSet := false
	for _, es := range api.ExceptionSets {
		hasExceptionSet = hasExceptionSet || es.UUID == exceptionSetUUID
	}
	hasAnalyticSet := false
	for _, as := range api.AnalyticSets {
		hasAnalyticSet = hasAnalyticSet || as.AnalyticSet.UUID == analyticSetUUID
	}
	if !hasExceptionSet || !hasAnalyticSet {
		return fmt.Errorf("plan %s: exception set attached=%t, analytic set attached=%t", planID, hasExceptionSet, hasAnalyticSet)
	}
	return nil
}

// testAccPlanOmittedSetsConfig creates a plan with advanced threat controls and tamper
// prevention enabled that says nothing about exception_sets or analytic_sets, plus an
// exception set and a custom analytic set for the test to attach out of band.
func testAccPlanOmittedSetsConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_configuration" "test" {
  name        = "%[1]s-ac"
  description = "Action config for plan test"

  alert_data_collection = {
    binary_included_data_attributes                = []
    synthetic_click_event_included_data_attributes = []
    download_event_included_data_attributes        = []
    file_included_data_attributes                  = []
    file_system_event_included_data_attributes     = []
    group_included_data_attributes                 = []
    process_event_included_data_attributes         = []
    process_included_data_attributes               = []
    screenshot_event_included_data_attributes      = []
    user_included_data_attributes                  = []
    gatekeeper_event_included_data_attributes      = []
    keylog_register_event_included_data_attributes = []
  }
}

resource "jamfprotect_analytic" "test" {
  name        = "%[1]s-analytic"
  sensor_type = "File System Event"
  description = "Analytic for the out-of-band analytic set"
  filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["terraform-test"]
  categories     = ["Testing"]
  snapshot_files = []

  add_to_jamf_pro_smart_group = false
  context_item                = []
}

resource "jamfprotect_analytic_set" "test" {
  name        = "%[1]s-as"
  description = "Attached to the plan out of band"
  analytics   = [jamfprotect_analytic.test.id]
}

resource "jamfprotect_exception_set" "test" {
  name        = "%[1]s-es"
  description = "Attached to the plan out of band"

  exceptions = [
    {
      type = "Process Event"
      rules = [
        {
          rule_type = "Process Path"
          value     = "/usr/bin/tf-acc-test"
        },
      ]
    },
  ]
}

resource "jamfprotect_plan" "test" {
  name                     = %[1]q
  description              = %[2]q
  action_configuration     = jamfprotect_action_configuration.test.id
  reporting_interval       = 1440
  advanced_threat_controls = "Block and report"
  tamper_prevention        = "Block and report"

  depends_on = [
    jamfprotect_analytic_set.test,
    jamfprotect_exception_set.test,
  ]
}
`, name, description)
}
