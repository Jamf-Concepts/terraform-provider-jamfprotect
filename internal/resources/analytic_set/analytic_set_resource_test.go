// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analyticset_test

import (
	"fmt"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAnalyticSetResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic-set")
	resourceName := "jamfprotect_analytic_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccAnalyticSetResourceConfig(rName, "Test analytic set description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test analytic set description"),
					resource.TestCheckResourceAttr(resourceName, "analytics.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
					resource.TestCheckResourceAttrSet(resourceName, "managed"),
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
				Config: testAccAnalyticSetResourceConfig(rName, "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func TestAccAnalyticSetResource_withTypes(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic-set")
	resourceName := "jamfprotect_analytic_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccAnalyticSetResourceConfigWithTypes(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "types.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "types.0", "Report"),
				),
			},
		},
	})
}

func testAccAnalyticSetResourceConfig(name, description string) string {
	return fmt.Sprintf(`
# First create an analytic to reference
resource "jamfprotect_analytic" "test" {
  name        = "%[1]s-analytic"
  input_type  = "GPFSEvent"
  description = "Test analytic for set"
  filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["terraform-test"]
  categories     = ["Testing"]
  snapshot_files = []

  analytic_actions = []
  context          = []
}

resource "jamfprotect_analytic_set" "test" {
  name        = %[1]q
  description = %[2]q
  analytics   = [jamfprotect_analytic.test.id]
}
`, name, description)
}

func testAccAnalyticSetResourceConfigWithTypes(name string) string {
	return fmt.Sprintf(`
# First create an analytic to reference
resource "jamfprotect_analytic" "test" {
  name        = "%[1]s-analytic"
  input_type  = "GPFSEvent"
  description = "Test analytic for set"
  filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["terraform-test"]
  categories     = ["Testing"]
  snapshot_files = []

  analytic_actions = []
  context          = []
}

resource "jamfprotect_analytic_set" "test" {
  name        = %[1]q
  description = "Analytic set with types"
  analytics   = [jamfprotect_analytic.test.id]
  types       = ["Report"]
}
`, name)
}
