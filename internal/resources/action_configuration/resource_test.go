// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package action_configuration_test

import (
	"fmt"
	"testing"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccActionConfigResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ac")
	resourceName := "jamfprotect_action_configuration.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
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
resource "jamfprotect_action_configuration" "test" {
  name        = %[1]q
  description = %[2]q

	data_collection = {
    data = {
			binary                     = { attrs = [], related = [] }
			synthetic_click_event      = { attrs = [], related = [] }
			download_event             = { attrs = [], related = [] }
			file                       = { attrs = [], related = [] }
			file_system_event          = { attrs = [], related = [] }
			group                      = { attrs = [], related = [] }
			process_event              = { attrs = [], related = [] }
			process                    = { attrs = [], related = [] }
			screenshot_event           = { attrs = [], related = [] }
			usb_event                  = { attrs = [], related = [] }
			user                       = { attrs = [], related = [] }
			gatekeeper_event           = { attrs = [], related = [] }
			keylog_register_event      = { attrs = [], related = [] }
			malware_removal_tool_event = { attrs = [], related = [] }
    }
  }
}
`, name, description)
}
