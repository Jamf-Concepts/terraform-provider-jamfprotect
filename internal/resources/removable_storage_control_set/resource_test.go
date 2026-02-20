// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

func TestAccRemovableStorageControlSetResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-usb")
	resourceName := "jamfprotect_removable_storage_control_set.test"

	if testing.Short() {
		t.Skip("skipping acceptance test")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			// Create and Read.
			{
				Config: testAccRemovableStorageControlSetResourceConfig(rName, "Acceptance test removable storage control set", "Read Only", "This removable storage device is limited to read-only."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Acceptance test removable storage control set"),
					resource.TestCheckResourceAttr(resourceName, "default_permission", "Read Only"),
				),
			},
			// Import.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update.
			{
				Config: testAccRemovableStorageControlSetResourceConfig(rName, "Updated removable storage control set", "Prevent", "Removable storage devices are not allowed."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated removable storage control set"),
					resource.TestCheckResourceAttr(resourceName, "default_permission", "Prevent"),
				),
			},
		},
	})
}

func testAccRemovableStorageControlSetResourceConfig(name, description, permission, message string) string {
	return fmt.Sprintf(`
resource "jamfprotect_removable_storage_control_set" "test" {
  name                 = %[1]q
  description          = %[2]q
	default_permission = %[3]q
  default_local_notification_message = %[4]q
}
`, name, description, permission, message)
}
