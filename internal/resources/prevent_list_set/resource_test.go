// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

// regexpMissingLists matches the API error raised for prevent list IDs that do not exist.
var regexpMissingLists = regexp.MustCompile(`Prevent lists not found`)

func testAccPreventListSetCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_prevent_list_set" {
			continue
		}
		result, err := c.GetPreventListSet(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("prevent list set %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccPreventListSetResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pls")
	resourceName := "jamfprotect_prevent_list_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccPreventListSetCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccPreventListSetResourceConfig(rName, "Test prevent list set description"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test prevent list set description"),
					resource.TestCheckResourceAttr(resourceName, "prevent_lists.#", "1"),
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
				Config: testAccPreventListSetResourceConfig(rName, "Updated description"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
			// Add a second filter to the set.
			{
				Config: testAccPreventListSetResourceConfigTwoLists(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "prevent_lists.#", "2"),
				),
			},
			// Membership can be cleared back to empty without recreating the set.
			{
				Config: testAccPreventListSetResourceConfigNoLists(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "prevent_lists.#", "0"),
				),
			},
		},
	})
}

func TestAccPreventListSetResource_emptyLists(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pls-empty")
	resourceName := "jamfprotect_prevent_list_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccPreventListSetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPreventListSetResourceConfigNoLists(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "prevent_lists.#", "0"),
				),
			},
		},
	})
}

// TestAccPreventListSetResource_missingList verifies that a prevent list ID
// which does not exist is rejected. Unlike unified logging filter sets, the API
// validates membership itself.
func TestAccPreventListSetResource_missingList(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pls-missing")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccPreventListSetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "jamfprotect_prevent_list_set" "test" {
  name          = %[1]q
  prevent_lists = ["999999999"]
}
`, rName),
				ExpectError: regexpMissingLists,
			},
		},
	})
}

func TestAccPreventListSetResource_planAssignment(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pls-plan")
	setResourceName := "jamfprotect_prevent_list_set.test"
	planResourceName := "jamfprotect_plan.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccPreventListSetCheckDestroy,
		Steps: []resource.TestStep{
			// The plan carries the assignment, and the set reports the plan back.
			{
				Config: testAccPreventListSetPlanConfig(rName, true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "prevent_list_sets.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(
						planResourceName, "prevent_list_sets.*",
						setResourceName, "id",
					),
				),
			},
			// Clearing the assignment with an explicit empty set detaches it, which is
			// also what lets the set be destroyed afterwards.
			{
				Config: testAccPreventListSetPlanConfig(rName, false),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "prevent_list_sets.#", "0"),
				),
			},
		},
	})
}

// TestAccPreventListSetResource_planOmittedNoDiff verifies that a plan
// configuration which never mentions prevent_list_sets does not diff
// against whatever Jamf Protect has assigned server-side. This is the case that
// protects existing plan configurations after the "Default" prevent list set is
// created by the Jamf Protect migration.
func TestAccPreventListSetResource_planOmittedNoDiff(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pls-omit")
	planResourceName := "jamfprotect_plan.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccPreventListSetPlanOnlyConfig(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(planResourceName, "id"),
					resource.TestCheckResourceAttrSet(planResourceName, "prevent_list_sets.#"),
				),
			},
			// A second no-op apply must stay empty, proving the computed value settles.
			{
				Config:   testAccPreventListSetPlanOnlyConfig(rName),
				PlanOnly: true,
			},
		},
	})
}

func testAccPreventListSetMemberConfig(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_custom_prevent_list" "test" {
  name         = "%[1]s-list"
  description  = "Prevent list for prevent list set acceptance test"
  prevent_type = "Team ID"
  list_data    = ["ABCDE12345"]
}
`, name)
}

func testAccPreventListSetResourceConfig(name, description string) string {
	return testAccPreventListSetMemberConfig(name) + fmt.Sprintf(`
resource "jamfprotect_prevent_list_set" "test" {
  name        = %[1]q
  description = %[2]q
  prevent_lists = [jamfprotect_custom_prevent_list.test.id]
}
`, name, description)
}

func testAccPreventListSetResourceConfigTwoLists(name string) string {
	return testAccPreventListSetMemberConfig(name) + fmt.Sprintf(`
resource "jamfprotect_custom_prevent_list" "second" {
  name         = "%[1]s-list-2"
  description  = "Second prevent list for prevent list set acceptance test"
  prevent_type = "Team ID"
  list_data    = ["FGHIJ67890"]
}

resource "jamfprotect_prevent_list_set" "test" {
  name        = %[1]q
  description = "Updated description"
  prevent_lists = [
    jamfprotect_custom_prevent_list.test.id,
    jamfprotect_custom_prevent_list.second.id,
  ]
}
`, name)
}

func testAccPreventListSetResourceConfigNoLists(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_prevent_list_set" "test" {
  name        = %[1]q
  description = "Updated description"
  prevent_lists = []
}
`, name)
}

func testAccPreventListSetActionConfig(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_configuration" "test" {
  name        = "%[1]s-ac"
  description = "Action config for prevent list set plan test"

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
`, name)
}

func testAccPreventListSetPlanConfig(name string, assigned bool) string {
	assignment := "prevent_list_sets = []"
	if assigned {
		assignment = "prevent_list_sets = [jamfprotect_prevent_list_set.test.id]"
	}

	return testAccPreventListSetMemberConfig(name) +
		testAccPreventListSetActionConfig(name) +
		fmt.Sprintf(`
resource "jamfprotect_prevent_list_set" "test" {
  name        = %[1]q
  description = "Prevent list set assigned to a plan"
  prevent_lists = [jamfprotect_custom_prevent_list.test.id]
}

resource "jamfprotect_plan" "test" {
  name                 = "%[1]s-plan"
  description          = "Plan for prevent list set acceptance test"
  action_configuration = jamfprotect_action_configuration.test.id
  reporting_interval   = 1440

  %[2]s
}
`, name, assignment)
}

func testAccPreventListSetPlanOnlyConfig(name string) string {
	return testAccPreventListSetActionConfig(name) + fmt.Sprintf(`
resource "jamfprotect_plan" "test" {
  name                 = "%[1]s-plan"
  description          = "Plan that never mentions prevent list sets"
  action_configuration = jamfprotect_action_configuration.test.id
  reporting_interval   = 1440
}
`, name)
}

// attachPreventListSetOutOfBand assigns a prevent list set to a plan directly through the API,
// without Terraform's involvement. It reproduces what the Jamf Protect
// PreventListSet migration does to every existing plan in a tenant that
// had custom prevent lists enabled: a "Default" set appears on plans that
// Terraform already manages and never asked for.
func attachPreventListSetOutOfBand(planID, preventListSetUUID string) error {
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

	input := jamfprotect.PlanInput{
		Name:                     api.Name,
		Description:              api.Description,
		AutoUpdate:               api.AutoUpdate,
		ThreatPreventionStrategy: api.ThreatPreventionStrategy,
		PreventListSets:          []string{preventListSetUUID},
	}
	if api.ActionConfigs != nil {
		input.ActionConfigs = api.ActionConfigs.ID
	}
	if api.CommsConfig != nil {
		input.CommsConfig = jamfprotect.PlanCommsConfigInput{
			FQDN:     api.CommsConfig.FQDN,
			Protocol: api.CommsConfig.Protocol,
		}
	}
	if api.InfoSync != nil {
		input.InfoSync = jamfprotect.PlanInfoSyncInput{
			Attrs:                api.InfoSync.Attrs,
			InsightsSyncInterval: api.InfoSync.InsightsSyncInterval,
		}
	}
	if api.SignaturesFeedConfig != nil {
		input.SignaturesFeedConfig = jamfprotect.PlanSignaturesFeedConfigInput{
			Mode: api.SignaturesFeedConfig.Mode,
		}
	}

	updated, err := c.UpdatePlan(ctx, planID, input)
	if err != nil {
		return fmt.Errorf("UpdatePlan(%s): %w", planID, err)
	}
	if len(updated.PreventListSets) != 1 {
		return fmt.Errorf("expected 1 prevent list set assigned out of band, got %d", len(updated.PreventListSets))
	}
	return nil
}

// TestAccPreventListSetResource_planMigrationAbsorbsDefaultSet is the
// regression test for the upgrade path. A plan configuration that predates prevent list
// sets — and therefore never mentions prevent_list_sets — must not
// produce a diff after Jamf Protect assigns a set to it server-side. If this test
// fails, adding the attribute is a breaking change for every existing plan in a
// migrated tenant.
func TestAccPreventListSetResource_planMigrationAbsorbsDefaultSet(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pls-migrate")
	planResourceName := "jamfprotect_plan.test"
	setResourceName := "jamfprotect_prevent_list_set.test"

	var planID, preventListSetUUID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccPreventListSetCheckDestroy,
		Steps: []resource.TestStep{
			// A plan that knows nothing about prevent list sets, plus an unassigned set.
			{
				Config: testAccPreventListSetMigrationConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					captureAttr(planResourceName, "id", &planID),
					captureAttr(setResourceName, "id", &preventListSetUUID),
					resource.TestCheckResourceAttr(planResourceName, "prevent_list_sets.#", "0"),
				),
			},
			// Simulate the migration, then re-plan the unchanged configuration.
			{
				PreConfig: func() {
					if err := attachPreventListSetOutOfBand(planID, preventListSetUUID); err != nil {
						t.Fatalf("failed to attach prevent list set out of band: %v", err)
					}
				},
				Config: testAccPreventListSetMigrationConfig(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Refreshed state now reflects the server-side assignment, still with no diff.
			{
				Config: testAccPreventListSetMigrationConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "prevent_list_sets.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(
						planResourceName, "prevent_list_sets.*",
						setResourceName, "id",
					),
				),
			},
			// Taking ownership: an explicit empty set detaches it again, which also
			// lets the set be destroyed at the end of the test.
			{
				Config: testAccPreventListSetMigrationConfigDetached(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "prevent_list_sets.#", "0"),
				),
			},
		},
	})
}

// captureAttr stores an attribute value from state for use in a later step.
func captureAttr(resourceName, attr string, target *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		value, ok := rs.Primary.Attributes[attr]
		if !ok {
			return fmt.Errorf("attribute %s not found on %s", attr, resourceName)
		}
		*target = value
		return nil
	}
}

func testAccPreventListSetMigrationConfig(name string) string {
	return testAccPreventListSetMemberConfig(name) +
		testAccPreventListSetActionConfig(name) +
		fmt.Sprintf(`
resource "jamfprotect_prevent_list_set" "test" {
  name        = %[1]q
  description = "Stands in for the migration-created Default set"
  prevent_lists = [jamfprotect_custom_prevent_list.test.id]
}

# Deliberately says nothing about prevent_list_sets, as a plan
# configuration written before the feature existed would not. depends_on gives
# the destroy ordering that an assignment would otherwise imply.
resource "jamfprotect_plan" "test" {
  name                 = "%[1]s-plan"
  description          = "Plan predating prevent list sets"
  action_configuration = jamfprotect_action_configuration.test.id
  reporting_interval   = 1440

  depends_on = [jamfprotect_prevent_list_set.test]
}
`, name)
}

func testAccPreventListSetMigrationConfigDetached(name string) string {
	return testAccPreventListSetMemberConfig(name) +
		testAccPreventListSetActionConfig(name) +
		fmt.Sprintf(`
resource "jamfprotect_prevent_list_set" "test" {
  name        = %[1]q
  description = "Stands in for the migration-created Default set"
  prevent_lists = [jamfprotect_custom_prevent_list.test.id]
}

resource "jamfprotect_plan" "test" {
  name                 = "%[1]s-plan"
  description          = "Plan predating prevent list sets"
  action_configuration = jamfprotect_action_configuration.test.id
  reporting_interval   = 1440

  prevent_list_sets = []
}
`, name)
}
