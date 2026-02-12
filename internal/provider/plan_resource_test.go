// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccPlanResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-plan")
	resourceName := "jamfprotect_plan.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccPlanResourceConfig(rName, "Test plan description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test plan description"),
					resource.TestCheckResourceAttr(resourceName, "auto_update", "true"),
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
				Config: testAccPlanResourceConfig(rName, "Updated plan description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated plan description"),
				),
			},
		},
	})
}

// testAccPlanResourceConfig creates a plan that depends on an action config.
// The action config is created inline to provide a valid action_configs ID.
func testAccPlanResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_config" "test" {
  name        = "%[1]s-ac"
  description = "Action config for plan test"
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

resource "jamfprotect_plan" "test" {
  name           = %[1]q
  description    = %[2]q
  action_configs = jamfprotect_action_config.test.id

  comms_config {
    fqdn     = "example.protect.jamfcloud.com"
    protocol = "MQTT"
  }

  info_sync {
    attrs                  = ["arch", "os_version"]
    insights_sync_interval = 86400
  }

  signatures_feed_config {
    mode = "ON"
  }
}
`, name, description)
}
