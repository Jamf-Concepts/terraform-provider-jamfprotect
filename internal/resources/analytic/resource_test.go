// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic_test

import (
	"fmt"
	"testing"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAnalyticResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccAnalyticResourceConfig(rName, "Test analytic description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test analytic description"),
					resource.TestCheckResourceAttr(resourceName, "sensor_type", "GPFSEvent"),
					resource.TestCheckResourceAttr(resourceName, "severity", "Informational"),
					resource.TestCheckResourceAttr(resourceName, "level", "0"),
					resource.TestCheckResourceAttr(resourceName, "tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.0", "terraform-test"),
					resource.TestCheckResourceAttr(resourceName, "categories.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "categories.0", "Testing"),
					resource.TestCheckResourceAttr(resourceName, "snapshot_files.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "add_to_jamf_pro_smart_group", "false"),
					resource.TestCheckResourceAttr(resourceName, "context_item.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
				),
			},
			// ImportState testing.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing.
			{
				Config: testAccAnalyticResourceConfig(rName, "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func TestAccAnalyticResource_withActions(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccAnalyticResourceConfigWithActions(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "add_to_jamf_pro_smart_group", "true"),
					resource.TestCheckResourceAttr(resourceName, "jamf_pro_smart_group_identifier", "smartgroup"),
					resource.TestCheckResourceAttr(resourceName, "context_item.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "context_item.0.name", "name"),
					resource.TestCheckResourceAttr(resourceName, "context_item.0.type", "String"),
				),
			},
		},
	})
}

func testAccAnalyticResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
	sensor_type  = "GPFSEvent"
  description = %[2]q
	predicate   = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["terraform-test"]
  categories     = ["Testing"]
  snapshot_files = []

	add_to_jamf_pro_smart_group = false
	context_item                 = []
}
`, name, description)
}

func testAccAnalyticResourceConfigWithActions(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
	sensor_type  = "GPFSEvent"
  description = "Analytic with actions"
	predicate   = "( $event.type == Filter )"
  level       = 0
  severity    = "Low"

  tags           = ["terraform-test"]
  categories     = ["Evasion"]
  snapshot_files = ["/tmp/snapshot.log"]

	add_to_jamf_pro_smart_group   = true
	jamf_pro_smart_group_identifier = "smartgroup"

	context_item = [{
    name  = "name"
    type  = "String"
		expressions = [""]
  }]
}
`, name)
}
