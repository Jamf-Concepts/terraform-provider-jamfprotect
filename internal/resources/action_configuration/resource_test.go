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

	alert_data_collection = {
		event_types = {
			binary                     = { extended_data_attributes = [] }
			synthetic_click_event      = { extended_data_attributes = [] }
			download_event             = { extended_data_attributes = [] }
			file                       = { extended_data_attributes = [] }
			file_system_event          = { extended_data_attributes = [] }
			group                      = { extended_data_attributes = [] }
			process_event              = { extended_data_attributes = [] }
			process                    = { extended_data_attributes = [] }
			screenshot_event           = { extended_data_attributes = [] }
			usb_event                  = { extended_data_attributes = [] }
			user                       = { extended_data_attributes = [] }
			gatekeeper_event           = { extended_data_attributes = [] }
			keylog_register_event      = { extended_data_attributes = [] }
			malware_removal_tool_event = { extended_data_attributes = [] }
		}
	}
}
`, name, description)
}
