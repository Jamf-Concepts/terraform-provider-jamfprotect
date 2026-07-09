// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set_test

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

const testAccExceptionSetListConfig = `
provider "jamfprotect" {}

list "jamfprotect_exception_set" "test" {
  provider = jamfprotect
}
`

const testAccExceptionSetListConfigExcludeBuiltins = `
provider "jamfprotect" {}

list "jamfprotect_exception_set" "test" {
  provider = jamfprotect

  config {
    exclude_builtins = true
  }
}
`

// TestAccExceptionSetListResource_excludeBuiltins verifies that a Jamf-managed
// built-in exception set is returned by default and excluded when
// exclude_builtins is set.
func TestAccExceptionSetListResource_excludeBuiltins(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	sets, err := c.ListExceptionSets(context.Background())
	if err != nil {
		t.Fatalf("listing exception sets: %v", err)
	}
	var builtinID string
	for _, s := range sets {
		if s.Managed {
			builtinID = s.UUID
			break
		}
	}
	if builtinID == "" {
		t.Skip("no managed built-in exception set present in test tenant")
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
				Config: testAccExceptionSetListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_exception_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccExceptionSetListConfigExcludeBuiltins,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_exception_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
		},
	})
}
