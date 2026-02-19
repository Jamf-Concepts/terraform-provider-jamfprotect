// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package user_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

// TestAccUserResource_basic validates create, read, update, and import behavior.
func TestAccUserResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-user")
	email := fmt.Sprintf("%s@example.com", rName)
	resourceName := "jamfprotect_user.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig(email, "1", true, "Medium"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "email", email),
					resource.TestCheckResourceAttr(resourceName, "identity_provider_id", "1"),
					resource.TestCheckResourceAttr(resourceName, "send_email_notifications", "true"),
					resource.TestCheckResourceAttr(resourceName, "email_severity", "Medium"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccUserResourceConfig(email, "1", false, "High"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "send_email_notifications", "false"),
					resource.TestCheckResourceAttr(resourceName, "email_severity", "High"),
				),
			},
		},
	})
}

// testAccUserResourceConfig builds Terraform configuration for a user resource.
func testAccUserResourceConfig(email, identityProviderID string, sendEmail bool, severity string) string {
	return fmt.Sprintf(`
resource "jamfprotect_user" "test" {
  email                    = %q
  identity_provider_id     = %q
  send_email_notifications = %t
  email_severity           = %q
}
`, email, identityProviderID, sendEmail, severity)
}
