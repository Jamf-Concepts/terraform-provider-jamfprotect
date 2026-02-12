// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccActionConfigResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ac")
	resourceName := "jamfprotect_action_config.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccActionConfigResourceConfig(rName, "Test action config"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test action config"),
					resource.TestCheckResourceAttrSet(resourceName, "hash"),
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
				Config: testAccActionConfigResourceConfig(rName, "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func testAccActionConfigResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_config" "test" {
  name        = %[1]q
  description = %[2]q
  alert_config = jsonencode({
    data = {
      binary             = { attrs = [], related = [] }
      clickEvent         = { attrs = [], related = [] }
      downloadEvent      = { attrs = [], related = [] }
      file               = { attrs = [], related = [] }
      fsEvent            = { attrs = [], related = [] }
      group              = { attrs = [], related = [] }
      procEvent          = { attrs = [], related = [] }
      process            = { attrs = [], related = [] }
      screenshotEvent    = { attrs = [], related = [] }
      usbEvent           = { attrs = [], related = [] }
      user               = { attrs = [], related = [] }
      gkEvent            = { attrs = [], related = [] }
      keylogRegisterEvent = { attrs = [], related = [] }
      mrtEvent           = { attrs = [], related = [] }
    }
  })
}
`, name, description)
}
