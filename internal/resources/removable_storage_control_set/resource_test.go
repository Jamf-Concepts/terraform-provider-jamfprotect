// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set_test

import (
	"testing"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccRemovableStorageControlSetResource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			// Create and Read.
			{
				Config: `
resource "jamfprotect_removable_storage_control_set" "test" {
  name                 = "tf-acc-test-removablestorage"
  description          = "Acceptance test removable storage control set"
	default_permission = "Read Only"
  default_local_notification_message = "This removable storage device is limited to read-only."
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("jamfprotect_removable_storage_control_set.test", "id"),
					resource.TestCheckResourceAttr("jamfprotect_removable_storage_control_set.test", "name", "tf-acc-test-removablestorage"),
					resource.TestCheckResourceAttr("jamfprotect_removable_storage_control_set.test", "default_permission", "Read Only"),
				),
			},
			// Import.
			{
				ResourceName:      "jamfprotect_removable_storage_control_set.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update.
			{
				Config: `
resource "jamfprotect_removable_storage_control_set" "test" {
  name                 = "tf-acc-test-removablestorage-updated"
  description          = "Updated removable storage control set"
	default_permission = "Prevent"
  default_local_notification_message = "Removable storage devices are not allowed."
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("jamfprotect_removable_storage_control_set.test", "name", "tf-acc-test-removablestorage-updated"),
					resource.TestCheckResourceAttr("jamfprotect_removable_storage_control_set.test", "default_permission", "Prevent"),
				),
			},
		},
	})
}
