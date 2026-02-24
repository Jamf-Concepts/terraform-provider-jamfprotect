// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func testAccActionConfigCheckDestroy(s *terraform.State) error {
	svc := testutil.TestAccService()
	if svc == nil {
		return fmt.Errorf("service not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_action_configuration" {
			continue
		}
		result, err := svc.GetActionConfig(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("action configuration %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccActionConfigResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ac")
	resourceName := "jamfprotect_action_configuration.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccActionConfigCheckDestroy,
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
		binary_included_data_attributes                     = ["Sha1", "Sha256", "Signing Information"]
		synthetic_click_event_included_data_attributes      = ["Process", "User", "Group"]
		download_event_included_data_attributes             = ["File"]
		file_included_data_attributes                       = ["Sha1", "Sha256", "User", "Group"]
		file_system_event_included_data_attributes          = ["File", "Process", "User", "Group"]
		group_included_data_attributes                      = ["Name"]
		process_event_included_data_attributes              = ["Process"]
		process_included_data_attributes                    = ["Args", "Binary", "User", "Group"]
		screenshot_event_included_data_attributes           = ["File"]
		user_included_data_attributes                       = ["Name"]
		gatekeeper_event_included_data_attributes           = ["Blocked Process", "Blocked Binary"]
		keylog_register_event_included_data_attributes      = ["Source Process", "Destination Process"]
	}
}
`, name, description)
}
