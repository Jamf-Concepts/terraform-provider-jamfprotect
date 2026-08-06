// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set_test

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
