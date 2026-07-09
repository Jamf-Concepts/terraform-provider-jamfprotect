// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package group_test

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

const testAccGroupListConfig = `
provider "jamfprotect" {}

list "jamfprotect_group" "test" {
  provider = jamfprotect
}
`

const testAccGroupListConfigExcludeBuiltins = `
provider "jamfprotect" {}

list "jamfprotect_group" "test" {
  provider = jamfprotect

  config {
    exclude_builtins = true
  }
}
`

// TestAccGroupListResource_excludeBuiltins verifies that the built-in "Default"
// group is returned by default and excluded when exclude_builtins is set.
func TestAccGroupListResource_excludeBuiltins(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	groups, err := c.ListGroups(context.Background())
	if err != nil {
		t.Fatalf("listing groups: %v", err)
	}
	var builtinID string
	for _, g := range groups {
		if g.Name == "Default" {
			builtinID = g.ID
			break
		}
	}
	if builtinID == "" {
		t.Skip("no built-in group present in test tenant")
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
				Config: testAccGroupListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_group.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccGroupListConfigExcludeBuiltins,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_group.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
		},
	})
}
