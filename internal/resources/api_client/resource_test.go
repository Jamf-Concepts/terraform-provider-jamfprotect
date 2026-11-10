// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package api_client_test

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

func testAccApiClientCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_api_client" {
			continue
		}
		result, err := c.GetApiClient(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("api client %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

// TestAccApiClientResource_basic validates create, import, and update behavior.
func TestAccApiClientResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-api-client")
	resourceName := "jamfprotect_api_client.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccApiClientCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccApiClientResourceConfig(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttrSet(resourceName, "password"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"password",
				},
			},
			{
				Config: testAccApiClientResourceConfig(rName + "-updated"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
				),
			},
		},
	})
}

// testAccApiClientResourceConfig builds Terraform configuration for an API client resource.
func testAccApiClientResourceConfig(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_api_client" "test" {
  name     = %q
  role_ids = ["1"]
}
`, name)
}

// TestAccApiClientResource_roleIDsNotImplicitAdmin validates that an unset role_ids creates a client
// with no roles rather than the Full Admin role the API assigns when roleIds is omitted, and that
// roles can be added and removed again.
func TestAccApiClientResource_roleIDsNotImplicitAdmin(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-apiclient")
	resourceName := "jamfprotect_api_client.test"
	emptyPlan := resource.ConfigPlanChecks{
		PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccApiClientCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:           testAccApiClientRoleIDsConfig(rName, ""),
				ConfigPlanChecks: emptyPlan,
				Check:            resource.TestCheckNoResourceAttr(resourceName, "role_ids.#"),
			},
			{
				Config:           testAccApiClientRoleIDsConfig(rName, `role_ids = ["1"]`),
				ConfigPlanChecks: emptyPlan,
				Check:            resource.TestCheckTypeSetElemAttr(resourceName, "role_ids.*", "1"),
			},
			{
				Config:           testAccApiClientRoleIDsConfig(rName, ""),
				ConfigPlanChecks: emptyPlan,
				Check:            resource.TestCheckNoResourceAttr(resourceName, "role_ids.#"),
			},
		},
	})
}

// testAccApiClientRoleIDsConfig builds an API client configuration with a caller-supplied role_ids line.
func testAccApiClientRoleIDsConfig(name, roleIDsLine string) string {
	return fmt.Sprintf(`
resource "jamfprotect_api_client" "test" {
  name = %q
  %s
}
`, name, roleIDsLine)
}
