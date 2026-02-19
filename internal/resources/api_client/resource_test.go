// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package api_client_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

// TestAccApiClientResource_basic validates create and import behavior.
func TestAccApiClientResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-api-client")
	resourceName := "jamfprotect_api_client.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
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
