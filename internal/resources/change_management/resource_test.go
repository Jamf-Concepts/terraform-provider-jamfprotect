// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package change_management_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

// TestAccChangeManagementResource_basic validates create, update, and import behavior.
func TestAccChangeManagementResource_basic(t *testing.T) {
	resourceName := "jamfprotect_change_management.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccChangeManagementResourceConfig(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "enable_freeze", "true"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccChangeManagementResourceConfig(false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "enable_freeze", "false"),
				),
			},
		},
	})
}

// testAccChangeManagementResourceConfig builds Terraform configuration for change management.
func testAccChangeManagementResourceConfig(enabled bool) string {
	return "resource \"jamfprotect_change_management\" \"test\" {\n  enable_freeze = " + boolToString(enabled) + "\n}\n"
}

// boolToString formats a bool as Terraform literal.
func boolToString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
