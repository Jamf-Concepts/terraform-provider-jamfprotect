// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration_test

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

const testAccActionConfigListConfig = `
provider "jamfprotect" {}

list "jamfprotect_action_configuration" "test" {
  provider = jamfprotect
}
`

const testAccActionConfigListConfigExcludeBuiltins = `
provider "jamfprotect" {}

list "jamfprotect_action_configuration" "test" {
  provider = jamfprotect

  config {
    exclude_builtins = true
  }
}
`

// TestAccActionConfigurationListResource_excludeBuiltins verifies that the
// built-in "Default" action configuration is returned by default and excluded
// when exclude_builtins is set.
func TestAccActionConfigurationListResource_excludeBuiltins(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	configs, err := c.ListActionConfigs(context.Background())
	if err != nil {
		t.Fatalf("listing action configurations: %v", err)
	}
	var builtinID string
	for _, ac := range configs {
		if ac.Name == "Default" {
			builtinID = ac.ID
			break
		}
	}
	if builtinID == "" {
		t.Skip("no built-in action configuration present in test tenant")
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
				Config: testAccActionConfigListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_action_configuration.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccActionConfigListConfigExcludeBuiltins,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_action_configuration.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(builtinID),
					}),
				},
			},
		},
	})
}
