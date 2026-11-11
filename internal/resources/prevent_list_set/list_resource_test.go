// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

const testAccPreventListSetListConfig = `
provider "jamfprotect" {}

list "jamfprotect_prevent_list_set" "test" {
  provider = jamfprotect
}
`

// testAccPreventListSetListConfigNamePrefix filters to a prefix that the
// seeded set cannot match.
const testAccPreventListSetListConfigNamePrefix = `
provider "jamfprotect" {}

list "jamfprotect_prevent_list_set" "test" {
  provider = jamfprotect

  config {
    name_prefix = "zzz-no-such-prevent-list-set"
  }
}
`

// seedPreventListSet creates a prevent list set directly through the API so its UUID is known
// before the query steps are constructed, and registers cleanup.
func seedPreventListSet(t *testing.T, name string) string {
	t.Helper()

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	ctx := context.Background()

	set, err := c.CreatePreventListSet(ctx, jamfprotect.PreventListSetInput{
		Name:         name,
		Description:  "Seeded for list resource acceptance test",
		PreventLists: []string{},
	})
	if err != nil {
		t.Fatalf("CreatePreventListSet: %v", err)
	}
	t.Cleanup(func() {
		if err := c.DeletePreventListSet(ctx, set.UUID); err != nil {
			t.Errorf("cleanup DeletePreventListSet: %v", err)
		}
	})

	return set.UUID
}

// TestAccPreventListSetListResource_basic verifies that a prevent list set is
// returned by an unfiltered query and excluded by a non-matching name_prefix.
func TestAccPreventListSetListResource_basic(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	setUUID := seedPreventListSet(t, acctest.RandomWithPrefix("tf-acc-pls-list"))

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Query:  true,
				Config: testAccPreventListSetListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_prevent_list_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(setUUID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccPreventListSetListConfigNamePrefix,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_prevent_list_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(setUUID),
					}),
				},
			},
		},
	})
}

// TestAccPreventListSetListResource_namePrefixMatches verifies that a
// matching name_prefix still returns the set, so the previous test's exclusion is
// attributable to the filter rather than to the set being absent.
func TestAccPreventListSetListResource_namePrefixMatches(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	name := acctest.RandomWithPrefix("tf-acc-pls-prefix")
	setUUID := seedPreventListSet(t, name)

	config := fmt.Sprintf(`
provider "jamfprotect" {}

list "jamfprotect_prevent_list_set" "test" {
  provider = jamfprotect

  config {
    name_prefix = %[1]q
  }
}
`, name)

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Query:  true,
				Config: config,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_prevent_list_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(setUUID),
					}),
				},
			},
		},
	})
}
