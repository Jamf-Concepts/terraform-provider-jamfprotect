// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package user_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func testAccUserCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_user" {
			continue
		}
		result, err := c.GetUser(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("user %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

// TestAccUserResource_basic validates create, read, update, and import behavior.
func TestAccUserResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-user")
	email := fmt.Sprintf("%s@example.com", rName)
	resourceName := "jamfprotect_user.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUserCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig(email, "1", true, "Medium"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "email", email),
					resource.TestCheckResourceAttr(resourceName, "identity_provider_id", "1"),
					resource.TestCheckResourceAttr(resourceName, "send_email_notifications", "true"),
					resource.TestCheckResourceAttr(resourceName, "email_severity", "Medium"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccUserResourceConfig(email, "1", false, "High"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
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

// TestAccUserResource_roleIDsLifecycle validates that null role_ids and group_ids are omitted on
// create, populated sets are sent, removing the attributes keeps the stored values, and known empty
// sets clear them.
func TestAccUserResource_roleIDsLifecycle(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-user")
	email := fmt.Sprintf("%s@example.com", rName)
	resourceName := "jamfprotect_user.test"
	emptyPlan := resource.ConfigPlanChecks{
		PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUserCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:           testAccUserRoleIDsConfig(email, ""),
				ConfigPlanChecks: emptyPlan,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "role_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "0"),
				),
			},
			{
				Config:           testAccUserRoleIDsConfig(email, `role_ids = ["1"]`+"\n  "+`group_ids = ["1"]`),
				ConfigPlanChecks: emptyPlan,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemAttr(resourceName, "role_ids.*", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "group_ids.*", "1"),
				),
			},
			{
				Config:           testAccUserRoleIDsConfig(email, ""),
				ConfigPlanChecks: emptyPlan,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemAttr(resourceName, "role_ids.*", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "group_ids.*", "1"),
				),
			},
			{
				Config:           testAccUserRoleIDsConfig(email, `role_ids = ["1"]`+"\n  "+`group_ids = []`),
				ConfigPlanChecks: emptyPlan,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemAttr(resourceName, "role_ids.*", "1"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "0"),
				),
			},
			{
				Config:           testAccUserRoleIDsConfig(email, `role_ids = []`+"\n  "+`group_ids = []`),
				ConfigPlanChecks: emptyPlan,
				Check:            resource.TestCheckResourceAttr(resourceName, "role_ids.#", "0"),
			},
		},
	})
}

// testAccUserRoleIDsConfig builds a user configuration with a caller-supplied role_ids line.
func testAccUserRoleIDsConfig(email, roleIDsLine string) string {
	return fmt.Sprintf(`
resource "jamfprotect_user" "test" {
  email                    = %q
  identity_provider_id     = "1"
  send_email_notifications = true
  email_severity           = "Medium"
  %s
}
`, email, roleIDsLine)
}
