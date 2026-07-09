// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_test

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

const testAccAnalyticListConfig = `
provider "jamfprotect" {}

list "jamfprotect_analytic" "test" {
  provider = jamfprotect
}
`

const testAccAnalyticListConfigExcludeBuiltins = `
provider "jamfprotect" {}

list "jamfprotect_analytic" "test" {
  provider = jamfprotect

  config {
    exclude_builtins = true
  }
}
`

// TestAccAnalyticListResource_excludeBuiltins verifies that a Jamf-provided
// analytic is returned by default and excluded when exclude_builtins is set.
func TestAccAnalyticListResource_excludeBuiltins(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	analytics, err := c.ListAnalytics(context.Background())
	if err != nil {
		t.Fatalf("listing analytics: %v", err)
	}
	var builtinID string
	for _, a := range analytics {
		if a.Jamf {
			builtinID = a.UUID
			break
		}
	}
	if builtinID == "" {
		t.Skip("no Jamf-provided analytic present in test tenant")
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
				Config: testAccAnalyticListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_analytic.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccAnalyticListConfigExcludeBuiltins,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_analytic.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
		},
	})
}
