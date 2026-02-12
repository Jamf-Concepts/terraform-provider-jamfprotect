// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccUSBControlSetResource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read.
			{
				Config: `
resource "jamfprotect_usb_control_set" "test" {
  name                 = "tf-acc-test-usb"
  description          = "Acceptance test USB control set"
  default_mount_action = "ReadOnly"
  default_message_action = "This removable storage device is limited to read-only."
  rules                = []
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("jamfprotect_usb_control_set.test", "id"),
					resource.TestCheckResourceAttr("jamfprotect_usb_control_set.test", "name", "tf-acc-test-usb"),
					resource.TestCheckResourceAttr("jamfprotect_usb_control_set.test", "default_mount_action", "ReadOnly"),
				),
			},
			// Import.
			{
				ResourceName:      "jamfprotect_usb_control_set.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update.
			{
				Config: `
resource "jamfprotect_usb_control_set" "test" {
  name                 = "tf-acc-test-usb-updated"
  description          = "Updated USB control set"
  default_mount_action = "Prevented"
  default_message_action = "USB devices are not allowed."
  rules                = []
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("jamfprotect_usb_control_set.test", "name", "tf-acc-test-usb-updated"),
					resource.TestCheckResourceAttr("jamfprotect_usb_control_set.test", "default_mount_action", "Prevented"),
				),
			},
		},
	})
}
