// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan_test

import (
	"fmt"
	"testing"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccPlanResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-plan")
	resourceName := "jamfprotect_plan.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
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
				ImportStateVerifyIgnore: []string{
					"updated", // Timestamp may change between create and import
				},
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
// The action config is created inline to provide a valid action_configuration ID.
func testAccPlanResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_configuration" "test" {
  name        = "%[1]s-ac"
  description = "Action config for plan test"

  alert_data_collection = {
    binary_included_data_attributes                     = []
    synthetic_click_event_included_data_attributes      = []
    download_event_included_data_attributes             = []
    file_included_data_attributes                       = []
    file_system_event_included_data_attributes          = []
    group_included_data_attributes                      = []
    process_event_included_data_attributes              = []
    process_included_data_attributes                    = []
    screenshot_event_included_data_attributes           = []
    user_included_data_attributes                       = []
    gatekeeper_event_included_data_attributes           = []
    keylog_register_event_included_data_attributes      = []
  }
}

resource "jamfprotect_plan" "test" {
	name                  = %[1]q
	description           = %[2]q
	action_configuration  = jamfprotect_action_configuration.test.id
	communications_protocol = "MQTT:443"
	reporting_interval    = 1440
	report_architecture   = true
	report_os_version     = true

	endpoint_threat_prevention = "Block and report"
}
`, name, description)
}
