// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list_test

import (
	"fmt"
	"testing"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCustomPreventListResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pl")
	resourceName := "jamfprotect_custom_prevent_list.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccCustomPreventListResourceConfig(rName, "Team ID", "Test prevent list"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "prevent_type", "Team ID"),
					resource.TestCheckResourceAttr(resourceName, "description", "Test prevent list"),
					resource.TestCheckResourceAttr(resourceName, "list_data.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "list_data.0", "ABC123DEF4"),
					resource.TestCheckResourceAttr(resourceName, "entry_count", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
				),
			},
			// ImportState testing.
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{},
			},
			// Update and Read testing.
			{
				Config: testAccCustomPreventListResourceConfig(rName, "TEAMID", "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func TestAccCustomPreventListResource_fileHash(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pl")
	resourceName := "jamfprotect_custom_prevent_list.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomPreventListResourceConfig(rName, "File Hash", "File hash list"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "prevent_type", "File Hash"),
				),
			},
		},
	})
}

func testAccCustomPreventListResourceConfig(name, listType, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_custom_prevent_list" "test" {
  name        = %[1]q
	prevent_type = %[2]q
  description = %[3]q
	list_data   = ["ABC123DEF4"]
}
`, name, listType, description)
}
