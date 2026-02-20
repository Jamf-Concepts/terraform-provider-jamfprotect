// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package group_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

func testAccGroupCheckDestroy(s *terraform.State) error {
	svc := testutil.TestAccService()
	if svc == nil {
		return fmt.Errorf("service not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_group" {
			continue
		}
		result, err := svc.GetGroup(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("group %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

// TestAccGroupResource_basic validates create, read, update, and import behavior.
func TestAccGroupResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-group")
	resourceName := "jamfprotect_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccGroupCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckTypeSetElemAttr(resourceName, "role_ids.*", "1"),
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
				Config: testAccGroupResourceConfig(rName + "-updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
				),
			},
		},
	})
}

// testAccGroupResourceConfig builds Terraform configuration for a group resource.
func testAccGroupResourceConfig(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_group" "test" {
  name         = %q
  role_ids     = ["1"]
}
`, name)
}
