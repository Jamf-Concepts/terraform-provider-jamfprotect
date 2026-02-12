// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccPreventListResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pl")
	resourceName := "jamfprotect_prevent_list.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccPreventListResourceConfig(rName, "TEAMID", "Test prevent list"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "type", "TEAMID"),
					resource.TestCheckResourceAttr(resourceName, "description", "Test prevent list"),
					resource.TestCheckResourceAttr(resourceName, "tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.0", "terraform-test"),
					resource.TestCheckResourceAttr(resourceName, "list.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "list.0", "ABC123DEF4"),
					resource.TestCheckResourceAttr(resourceName, "entry_count", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
				),
			},
			// ImportState testing.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// Tags are not returned by getPreventList.
				ImportStateVerifyIgnore: []string{"tags"},
			},
			// Update and Read testing.
			{
				Config: testAccPreventListResourceConfig(rName, "TEAMID", "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func TestAccPreventListResource_fileHash(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pl")
	resourceName := "jamfprotect_prevent_list.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPreventListResourceConfig(rName, "FILEHASH", "File hash list"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "type", "FILEHASH"),
				),
			},
		},
	})
}

func testAccPreventListResourceConfig(name, listType, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_prevent_list" "test" {
  name        = %[1]q
  type        = %[2]q
  description = %[3]q
  tags        = ["terraform-test"]
  list        = ["ABC123DEF4"]
}
`, name, listType, description)
}
