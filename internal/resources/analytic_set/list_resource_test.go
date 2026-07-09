// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_set_test

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

const testAccAnalyticSetListConfig = `
provider "jamfprotect" {}

list "jamfprotect_analytic_set" "test" {
  provider = jamfprotect
}
`

const testAccAnalyticSetListConfigExcludeBuiltins = `
provider "jamfprotect" {}

list "jamfprotect_analytic_set" "test" {
  provider = jamfprotect

  config {
    exclude_builtins = true
  }
}
`

// systemAnalyticSetNames mirrors the built-in analytic set names filtered by the
// provider; kept local to the external test package.
var systemAnalyticSetTestNames = map[string]struct{}{
	"Advanced Threat Controls": {},
	"Tamper Prevention":        {},
	"Default Analytic Set":     {},
}

// TestAccAnalyticSetListResource_excludeBuiltins verifies that a built-in
// (system) analytic set is returned by default and excluded when
// exclude_builtins is set.
func TestAccAnalyticSetListResource_excludeBuiltins(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	sets, err := c.ListAnalyticSets(context.Background())
	if err != nil {
		t.Fatalf("listing analytic sets: %v", err)
	}
	var builtinID string
	for _, s := range sets {
		if _, ok := systemAnalyticSetTestNames[s.Name]; ok {
			builtinID = s.UUID
			break
		}
	}
	if builtinID == "" {
		t.Skip("no built-in analytic set present in test tenant")
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
				Config: testAccAnalyticSetListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_analytic_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccAnalyticSetListConfigExcludeBuiltins,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_analytic_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
		},
	})
}
