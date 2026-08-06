// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set_test

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

// regexpMissingFilters matches the diagnostic raised for filter UUIDs that do not exist.
var regexpMissingFilters = regexp.MustCompile(`Referenced unified logging filters missing`)

func testAccUnifiedLoggingFilterSetCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_unified_logging_filter_set" {
			continue
		}
		result, err := c.GetUnifiedLoggingFilterSet(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("unified logging filter set %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccUnifiedLoggingFilterSetResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulfs")
	resourceName := "jamfprotect_unified_logging_filter_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUnifiedLoggingFilterSetCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccUnifiedLoggingFilterSetResourceConfig(rName, "Test filter set description"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test filter set description"),
					resource.TestCheckResourceAttr(resourceName, "filters.#", "1"),
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
				Config: testAccUnifiedLoggingFilterSetResourceConfig(rName, "Updated description"),
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
				Config: testAccUnifiedLoggingFilterSetResourceConfigTwoFilters(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "filters.#", "2"),
				),
			},
			// Membership can be cleared back to empty without recreating the set.
			{
				Config: testAccUnifiedLoggingFilterSetResourceConfigNoFilters(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "filters.#", "0"),
				),
			},
		},
	})
}

func TestAccUnifiedLoggingFilterSetResource_emptyFilters(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulfs-empty")
	resourceName := "jamfprotect_unified_logging_filter_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUnifiedLoggingFilterSetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccUnifiedLoggingFilterSetResourceConfigNoFilters(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "filters.#", "0"),
				),
			},
		},
	})
}

// TestAccUnifiedLoggingFilterSetResource_missingFilter verifies that a filter UUID
// which does not exist is rejected at plan time. The API accepts unknown UUIDs
// silently and creates a set with no members, so the provider has to catch it.
func TestAccUnifiedLoggingFilterSetResource_missingFilter(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulfs-missing")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUnifiedLoggingFilterSetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter_set" "test" {
  name    = %[1]q
  filters = ["8c1f4b0e-0000-4000-8000-000000000000"]
}
`, rName),
				ExpectError: regexpMissingFilters,
			},
		},
	})
}

func TestAccUnifiedLoggingFilterSetResource_planAssignment(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulfs-plan")
	setResourceName := "jamfprotect_unified_logging_filter_set.test"
	planResourceName := "jamfprotect_plan.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUnifiedLoggingFilterSetCheckDestroy,
		Steps: []resource.TestStep{
			// The plan carries the assignment, and the set reports the plan back.
			{
				Config: testAccUnifiedLoggingFilterSetPlanConfig(rName, true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "unified_logging_filter_sets.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(
						planResourceName, "unified_logging_filter_sets.*",
						setResourceName, "id",
					),
				),
			},
			// Clearing the assignment with an explicit empty set detaches it, which is
			// also what lets the set be destroyed afterwards.
			{
				Config: testAccUnifiedLoggingFilterSetPlanConfig(rName, false),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "unified_logging_filter_sets.#", "0"),
				),
			},
		},
	})
}

// TestAccUnifiedLoggingFilterSetResource_planOmittedNoDiff verifies that a plan
// configuration which never mentions unified_logging_filter_sets does not diff
// against whatever Jamf Protect has assigned server-side. This is the case that
// protects existing plan configurations after the "Default" filter set is
// created by the Jamf Protect migration.
func TestAccUnifiedLoggingFilterSetResource_planOmittedNoDiff(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulfs-omit")
	planResourceName := "jamfprotect_plan.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccUnifiedLoggingFilterSetPlanOnlyConfig(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(planResourceName, "id"),
					resource.TestCheckResourceAttrSet(planResourceName, "unified_logging_filter_sets.#"),
				),
			},
			// A second no-op apply must stay empty, proving the computed value settles.
			{
				Config:   testAccUnifiedLoggingFilterSetPlanOnlyConfig(rName),
				PlanOnly: true,
			},
		},
	})
}

func testAccUnifiedLoggingFilterSetFilterConfig(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter" "test" {
  name        = "%[1]s-filter"
  description = "Filter for filter set acceptance test"
  filter      = "subsystem == \"com.apple.TimeMachine\""
  tags        = ["terraform-test"]
}
`, name)
}

func testAccUnifiedLoggingFilterSetResourceConfig(name, description string) string {
	return testAccUnifiedLoggingFilterSetFilterConfig(name) + fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter_set" "test" {
  name        = %[1]q
  description = %[2]q
  filters     = [jamfprotect_unified_logging_filter.test.id]
}
`, name, description)
}

func testAccUnifiedLoggingFilterSetResourceConfigTwoFilters(name string) string {
	return testAccUnifiedLoggingFilterSetFilterConfig(name) + fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter" "second" {
  name        = "%[1]s-filter-2"
  description = "Second filter for filter set acceptance test"
  filter      = "subsystem == \"com.apple.screensharing\""
  tags        = ["terraform-test"]
}

resource "jamfprotect_unified_logging_filter_set" "test" {
  name        = %[1]q
  description = "Updated description"
  filters = [
    jamfprotect_unified_logging_filter.test.id,
    jamfprotect_unified_logging_filter.second.id,
  ]
}
`, name)
}

func testAccUnifiedLoggingFilterSetResourceConfigNoFilters(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter_set" "test" {
  name        = %[1]q
  description = "Updated description"
  filters     = []
}
`, name)
}

func testAccUnifiedLoggingFilterSetActionConfig(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_configuration" "test" {
  name        = "%[1]s-ac"
  description = "Action config for filter set plan test"

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

func testAccUnifiedLoggingFilterSetPlanConfig(name string, assigned bool) string {
	assignment := "unified_logging_filter_sets = []"
	if assigned {
		assignment = "unified_logging_filter_sets = [jamfprotect_unified_logging_filter_set.test.id]"
	}

	return testAccUnifiedLoggingFilterSetFilterConfig(name) +
		testAccUnifiedLoggingFilterSetActionConfig(name) +
		fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter_set" "test" {
  name        = %[1]q
  description = "Filter set assigned to a plan"
  filters     = [jamfprotect_unified_logging_filter.test.id]
}

resource "jamfprotect_plan" "test" {
  name                 = "%[1]s-plan"
  description          = "Plan for filter set acceptance test"
  action_configuration = jamfprotect_action_configuration.test.id
  reporting_interval   = 1440

  %[2]s
}
`, name, assignment)
}

func testAccUnifiedLoggingFilterSetPlanOnlyConfig(name string) string {
	return testAccUnifiedLoggingFilterSetActionConfig(name) + fmt.Sprintf(`
resource "jamfprotect_plan" "test" {
  name                 = "%[1]s-plan"
  description          = "Plan that never mentions unified logging filter sets"
  action_configuration = jamfprotect_action_configuration.test.id
  reporting_interval   = 1440
}
`, name)
}

// attachFilterSetOutOfBand assigns a filter set to a plan directly through the API,
// without Terraform's involvement. It reproduces what the Jamf Protect
// UnifiedLoggingFilterSet migration does to every existing plan in a tenant that
// had unified logging filters enabled: a "Default" set appears on plans that
// Terraform already manages and never asked for.
func attachFilterSetOutOfBand(planID, filterSetUUID string) error {
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
		UnifiedLoggingFilterSets: []string{filterSetUUID},
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
	if len(updated.UnifiedLoggingFilterSets) != 1 {
		return fmt.Errorf("expected 1 filter set assigned out of band, got %d", len(updated.UnifiedLoggingFilterSets))
	}
	return nil
}

// TestAccUnifiedLoggingFilterSetResource_planMigrationAbsorbsDefaultSet is the
// regression test for the upgrade path. A plan configuration that predates filter
// sets — and therefore never mentions unified_logging_filter_sets — must not
// produce a diff after Jamf Protect assigns a set to it server-side. If this test
// fails, adding the attribute is a breaking change for every existing plan in a
// migrated tenant.
func TestAccUnifiedLoggingFilterSetResource_planMigrationAbsorbsDefaultSet(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulfs-migrate")
	planResourceName := "jamfprotect_plan.test"
	setResourceName := "jamfprotect_unified_logging_filter_set.test"

	var planID, filterSetUUID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUnifiedLoggingFilterSetCheckDestroy,
		Steps: []resource.TestStep{
			// A plan that knows nothing about filter sets, plus an unassigned set.
			{
				Config: testAccUnifiedLoggingFilterSetMigrationConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					captureAttr(planResourceName, "id", &planID),
					captureAttr(setResourceName, "id", &filterSetUUID),
					resource.TestCheckResourceAttr(planResourceName, "unified_logging_filter_sets.#", "0"),
				),
			},
			// Simulate the migration, then re-plan the unchanged configuration.
			{
				PreConfig: func() {
					if err := attachFilterSetOutOfBand(planID, filterSetUUID); err != nil {
						t.Fatalf("failed to attach filter set out of band: %v", err)
					}
				},
				Config: testAccUnifiedLoggingFilterSetMigrationConfig(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Refreshed state now reflects the server-side assignment, still with no diff.
			{
				Config: testAccUnifiedLoggingFilterSetMigrationConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "unified_logging_filter_sets.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(
						planResourceName, "unified_logging_filter_sets.*",
						setResourceName, "id",
					),
				),
			},
			// Taking ownership: an explicit empty set detaches it again, which also
			// lets the set be destroyed at the end of the test.
			{
				Config: testAccUnifiedLoggingFilterSetMigrationConfigDetached(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(planResourceName, "unified_logging_filter_sets.#", "0"),
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

func testAccUnifiedLoggingFilterSetMigrationConfig(name string) string {
	return testAccUnifiedLoggingFilterSetFilterConfig(name) +
		testAccUnifiedLoggingFilterSetActionConfig(name) +
		fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter_set" "test" {
  name        = %[1]q
  description = "Stands in for the migration-created Default set"
  filters     = [jamfprotect_unified_logging_filter.test.id]
}

# Deliberately says nothing about unified_logging_filter_sets, as a plan
# configuration written before the feature existed would not. depends_on gives
# the destroy ordering that an assignment would otherwise imply.
resource "jamfprotect_plan" "test" {
  name                 = "%[1]s-plan"
  description          = "Plan predating unified logging filter sets"
  action_configuration = jamfprotect_action_configuration.test.id
  reporting_interval   = 1440

  depends_on = [jamfprotect_unified_logging_filter_set.test]
}
`, name)
}

func testAccUnifiedLoggingFilterSetMigrationConfigDetached(name string) string {
	return testAccUnifiedLoggingFilterSetFilterConfig(name) +
		testAccUnifiedLoggingFilterSetActionConfig(name) +
		fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter_set" "test" {
  name        = %[1]q
  description = "Stands in for the migration-created Default set"
  filters     = [jamfprotect_unified_logging_filter.test.id]
}

resource "jamfprotect_plan" "test" {
  name                 = "%[1]s-plan"
  description          = "Plan predating unified logging filter sets"
  action_configuration = jamfprotect_action_configuration.test.id
  reporting_interval   = 1440

  unified_logging_filter_sets = []
}
`, name)
}
