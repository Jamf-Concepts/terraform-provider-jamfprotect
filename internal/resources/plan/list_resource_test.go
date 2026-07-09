// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan_test

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

const testAccPlanListConfig = `
provider "jamfprotect" {}

list "jamfprotect_plan" "test" {
  provider = jamfprotect
}
`

const testAccPlanListConfigExcludeBuiltins = `
provider "jamfprotect" {}

list "jamfprotect_plan" "test" {
  provider = jamfprotect

  config {
    exclude_builtins = true
  }
}
`

// TestAccPlanListResource_excludeBuiltins verifies that the built-in "Default"
// plan is returned by default and excluded when exclude_builtins is set.
func TestAccPlanListResource_excludeBuiltins(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	// Resolve the built-in plan's id so we can assert its presence/absence.
	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	plans, err := c.ListPlans(context.Background())
	if err != nil {
		t.Fatalf("listing plans: %v", err)
	}
	var builtinID string
	for _, p := range plans {
		if p.Name == "Default" {
			builtinID = p.ID
			break
		}
	}
	if builtinID == "" {
		t.Skip("no built-in plan present in test tenant")
	}

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Query:  true,
				Config: testAccPlanListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_plan.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccPlanListConfigExcludeBuiltins,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_plan.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
		},
	})
}
