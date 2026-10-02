// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

// testAccAnalyticManagedEnv gates acceptance tests that change tenant overrides on a shared
// Jamf-managed analytic.
const testAccAnalyticManagedEnv = "TF_ACC_ANALYTIC_MANAGED_TEST"

// testAccPickUnmodifiedJamfAnalytic returns a Jamf-managed analytic that has no tenant
// overrides and carries a long description and remediation, so a refresh after update is
// exercised against fields the update mutation does not return.
func testAccPickUnmodifiedJamfAnalytic(t *testing.T, c *jamfprotect.Client) *jamfprotect.Analytic {
	t.Helper()
	analytics, err := c.ListAnalytics(context.Background())
	if err != nil {
		t.Fatalf("listing analytics: %s", err)
	}
	for _, candidate := range analytics {
		if !candidate.Jamf || candidate.LongDescription == "" || candidate.Remediation == "" {
			continue
		}
		a, err := c.GetAnalytic(context.Background(), candidate.UUID)
		if err != nil {
			t.Fatalf("reading analytic %s: %s", candidate.UUID, err)
		}
		if a != nil && a.TenantActions == nil && a.TenantSeverity == "" {
			return a
		}
	}
	t.Skip("no Jamf-managed analytic without tenant overrides found in the tenant")
	return nil
}

// testAccResetAnalyticOverrides clears tenant overrides on a Jamf-managed analytic, since the
// resource's Delete only removes it from state.
func testAccResetAnalyticOverrides(t *testing.T, c *jamfprotect.Client, uuid string) {
	t.Helper()
	input := jamfprotect.InternalAnalyticInput{TenantActionsNull: true, TenantSeverityNull: true}
	if _, err := c.UpdateInternalAnalytic(context.Background(), uuid, input); err != nil {
		t.Errorf("resetting tenant overrides on analytic %s: %s", uuid, err)
	}
}

// testAccCheckAnalyticOverrides verifies the tenant overrides stored on the server.
func testAccCheckAnalyticOverrides(c *jamfprotect.Client, uuid, wantSeverity string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		a, err := c.GetAnalytic(context.Background(), uuid)
		if err != nil {
			return fmt.Errorf("reading analytic %s: %w", uuid, err)
		}
		if a == nil {
			return fmt.Errorf("analytic %s not found", uuid)
		}
		if a.TenantActions != nil {
			return fmt.Errorf("expected tenantActions to stay null, got %v", a.TenantActions)
		}
		if a.TenantSeverity != wantSeverity {
			return fmt.Errorf("expected tenantSeverity %q, got %q", wantSeverity, a.TenantSeverity)
		}
		return nil
	}
}

// TestAccAnalyticManagedResource_severityOnly imports a Jamf-managed analytic with no tenant
// overrides, sets only tenant_severity, and checks that the update applies cleanly without
// sending a tenant_actions override.
//
// It changes overrides on a shared Jamf analytic and resets them afterwards. To run it, set:
//
//	TF_ACC_ANALYTIC_MANAGED_TEST=1
func TestAccAnalyticManagedResource_severityOnly(t *testing.T) {
	if os.Getenv(testAccAnalyticManagedEnv) != "1" {
		t.Skip("Skipping analytic_managed test because it changes a shared Jamf analytic. " +
			"Set " + testAccAnalyticManagedEnv + "=1 to run.")
	}
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}
	testutil.TestAccPreCheck(t)

	c := testutil.TestAccClient()
	analytic := testAccPickUnmodifiedJamfAnalytic(t, c)
	t.Cleanup(func() { testAccResetAnalyticOverrides(t, c, analytic.UUID) })

	resourceName := "jamfprotect_analytic_managed.test"
	config := testAccAnalyticManagedResourceConfig("Low")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config:             config,
				ResourceName:       resourceName,
				ImportState:        true,
				ImportStateId:      analytic.UUID,
				ImportStatePersist: true,
			},
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tenant_severity"), knownvalue.StringExact("Low")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tenant_actions"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("long_description"), knownvalue.StringExact(analytic.LongDescription)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("remediation"), knownvalue.StringExact(analytic.Remediation)),
				},
				Check: testAccCheckAnalyticOverrides(c, analytic.UUID, "Low"),
			},
		},
	})
}

// testAccAnalyticManagedResourceConfig returns a configuration that sets only tenant_severity.
func testAccAnalyticManagedResourceConfig(severity string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic_managed" "test" {
  tenant_severity = %q
}
`, severity)
}
