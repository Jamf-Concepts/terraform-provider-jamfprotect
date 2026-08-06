// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set_test

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

const testAccUnifiedLoggingFilterSetListConfig = `
provider "jamfprotect" {}

list "jamfprotect_unified_logging_filter_set" "test" {
  provider = jamfprotect
}
`

// testAccUnifiedLoggingFilterSetListConfigNamePrefix filters to a prefix that the
// seeded set cannot match.
const testAccUnifiedLoggingFilterSetListConfigNamePrefix = `
provider "jamfprotect" {}

list "jamfprotect_unified_logging_filter_set" "test" {
  provider = jamfprotect

  config {
    name_prefix = "zzz-no-such-filter-set"
  }
}
`

// seedFilterSet creates a filter set directly through the API so its UUID is known
// before the query steps are constructed, and registers cleanup.
func seedFilterSet(t *testing.T, name string) string {
	t.Helper()

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	ctx := context.Background()

	set, err := c.CreateUnifiedLoggingFilterSet(ctx, jamfprotect.UnifiedLoggingFilterSetInput{
		Name:        name,
		Description: "Seeded for list resource acceptance test",
		Filters:     []string{},
	})
	if err != nil {
		t.Fatalf("CreateUnifiedLoggingFilterSet: %v", err)
	}
	t.Cleanup(func() {
		if err := c.DeleteUnifiedLoggingFilterSet(ctx, set.UUID); err != nil {
			t.Errorf("cleanup DeleteUnifiedLoggingFilterSet: %v", err)
		}
	})

	return set.UUID
}

// TestAccUnifiedLoggingFilterSetListResource_basic verifies that a filter set is
// returned by an unfiltered query and excluded by a non-matching name_prefix.
func TestAccUnifiedLoggingFilterSetListResource_basic(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	setUUID := seedFilterSet(t, acctest.RandomWithPrefix("tf-acc-ulfs-list"))

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_14_0),
		},
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Query:  true,
				Config: testAccUnifiedLoggingFilterSetListConfig,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("jamfprotect_unified_logging_filter_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(setUUID),
					}),
				},
			},
			{
				Query:  true,
				Config: testAccUnifiedLoggingFilterSetListConfigNamePrefix,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectNoIdentity("jamfprotect_unified_logging_filter_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(setUUID),
					}),
				},
			},
		},
	})
}

// TestAccUnifiedLoggingFilterSetListResource_namePrefixMatches verifies that a
// matching name_prefix still returns the set, so the previous test's exclusion is
// attributable to the filter rather than to the set being absent.
func TestAccUnifiedLoggingFilterSetListResource_namePrefixMatches(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}

	name := acctest.RandomWithPrefix("tf-acc-ulfs-prefix")
	setUUID := seedFilterSet(t, name)

	config := fmt.Sprintf(`
provider "jamfprotect" {}

list "jamfprotect_unified_logging_filter_set" "test" {
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
					querycheck.ExpectIdentity("jamfprotect_unified_logging_filter_set.test", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(setUUID),
					}),
				},
			},
		},
	})
}
