// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package api_client_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

func testAccApiClientCheckDestroy(s *terraform.State) error {
	svc := testutil.TestAccService()
	if svc == nil {
		return fmt.Errorf("service not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_api_client" {
			continue
		}
		result, err := svc.GetApiClient(context.Background(), rs.Primary.ID)
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
