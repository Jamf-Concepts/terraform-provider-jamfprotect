// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func TestAccUnifiedLoggingFilterSetsDataSource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulfs-ds")
	dataSourceName := "data.jamfprotect_unified_logging_filter_sets.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUnifiedLoggingFilterSetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccUnifiedLoggingFilterSetsDataSourceConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "unified_logging_filter_sets.#"),
					// Located by UUID rather than index, since the list is sorted by name
					// and the tenant may hold unrelated filter sets.
					resource.TestCheckOutput("found_name", rName),
					resource.TestCheckOutput("found_filter_count", "1"),
					resource.TestCheckOutput("found_plan_count", "0"),
				),
			},
		},
	})
}

func testAccUnifiedLoggingFilterSetsDataSourceConfig(name string) string {
	return testAccUnifiedLoggingFilterSetResourceConfig(name, "Data source acceptance test") + `
data "jamfprotect_unified_logging_filter_sets" "test" {
  depends_on = [jamfprotect_unified_logging_filter_set.test]
}

locals {
  matched = [
    for set in data.jamfprotect_unified_logging_filter_sets.test.unified_logging_filter_sets :
    set if set.uuid == jamfprotect_unified_logging_filter_set.test.id
  ]
}

output "found_name" {
  value = local.matched[0].name
}

output "found_filter_count" {
  value = length(local.matched[0].filters)
}

output "found_plan_count" {
  value = length(local.matched[0].plans)
}
`
}
