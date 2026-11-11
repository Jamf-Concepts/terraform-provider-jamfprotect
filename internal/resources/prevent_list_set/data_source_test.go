// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func TestAccPreventListSetsDataSource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pls-ds")
	dataSourceName := "data.jamfprotect_prevent_list_sets.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccPreventListSetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPreventListSetsDataSourceConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "prevent_list_sets.#"),
					// Located by UUID rather than index, since the list is sorted by name
					// and the tenant may hold unrelated prevent list sets.
					resource.TestCheckOutput("found_name", rName),
					resource.TestCheckOutput("found_prevent_list_count", "1"),
					resource.TestCheckOutput("found_plan_count", "0"),
				),
			},
		},
	})
}

func testAccPreventListSetsDataSourceConfig(name string) string {
	return testAccPreventListSetResourceConfig(name, "Data source acceptance test") + `
data "jamfprotect_prevent_list_sets" "test" {
  depends_on = [jamfprotect_prevent_list_set.test]
}

locals {
  matched = [
    for set in data.jamfprotect_prevent_list_sets.test.prevent_list_sets :
    set if set.uuid == jamfprotect_prevent_list_set.test.id
  ]
}

output "found_name" {
  value = local.matched[0].name
}

output "found_prevent_list_count" {
  value = length(local.matched[0].prevent_lists)
}

output "found_plan_count" {
  value = length(local.matched[0].plans)
}
`
}
