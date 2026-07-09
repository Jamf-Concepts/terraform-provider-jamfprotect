// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package role_test

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

const testAccRoleListConfig = `
provider "jamfprotect" {}

list "jamfprotect_role" "test" {
  provider = jamfprotect
}
`

const testAccRoleListConfigExcludeBuiltins = `
provider "jamfprotect" {}

list "jamfprotect_role" "test" {
  provider = jamfprotect

  config {
    exclude_builtins = true
  }
}
`

// TestAccRoleListResource_excludeBuiltins verifies that a built-in role
// (Full Admin / Read Only) is returned by default and excluded when
// exclude_builtins is set.
func TestAccRoleListResource_excludeBuiltins(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	roles, err := c.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("listing roles: %v", err)
	}
	var builtinID string
	for _, r := range roles {
		if r.Name == "Full Admin" || r.Name == "Read Only" {
			builtinID = r.ID
			break
		}
	}
	if builtinID == "" {
		t.Skip("no built-in role present in test tenant")
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
				Config: testAccRoleListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_role.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccRoleListConfigExcludeBuiltins,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_role.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
		},
	})
}
