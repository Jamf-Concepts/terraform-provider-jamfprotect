// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccAnalyticResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccAnalyticResourceConfig(rName, "Test analytic description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test analytic description"),
					resource.TestCheckResourceAttr(resourceName, "input_type", "GPFSEvent"),
					resource.TestCheckResourceAttr(resourceName, "severity", "Informational"),
					resource.TestCheckResourceAttr(resourceName, "level", "0"),
					resource.TestCheckResourceAttr(resourceName, "tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.0", "terraform-test"),
					resource.TestCheckResourceAttr(resourceName, "categories.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "categories.0", "Testing"),
					resource.TestCheckResourceAttr(resourceName, "snapshot_files.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "analytic_actions.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "context.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
				),
			},
			// ImportState testing.
			{
				ResourceName: resourceName,
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return "", fmt.Errorf("resource not found: %s", resourceName)
					}
					return rs.Primary.Attributes["uuid"], nil
				},
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "uuid",
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
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAnalyticResourceConfigWithActions(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "analytic_actions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "analytic_actions.0.name", "SmartGroup"),
					resource.TestCheckResourceAttr(resourceName, "analytic_actions.0.parameters", `{"id":"smartgroup"}`),
					resource.TestCheckResourceAttr(resourceName, "context.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "context.0.name", "name"),
					resource.TestCheckResourceAttr(resourceName, "context.0.type", "String"),
				),
			},
		},
	})
}

func testAccAnalyticResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
  input_type  = "GPFSEvent"
  description = %[2]q
  filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["terraform-test"]
  categories     = ["Testing"]
  snapshot_files = []

  analytic_actions = []
  context          = []
}
`, name, description)
}

func testAccAnalyticResourceConfigWithActions(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
  input_type  = "GPFSEvent"
  description = "Analytic with actions"
  filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Low"

  tags           = ["terraform-test"]
  categories     = ["Evasion"]
  snapshot_files = ["/tmp/snapshot.log"]

  analytic_actions = [{
    name       = "SmartGroup"
    parameters = "{\"id\":\"smartgroup\"}"
  }]

  context = [{
    name  = "name"
    type  = "String"
    exprs = [""]
  }]
}
`, name)
}
