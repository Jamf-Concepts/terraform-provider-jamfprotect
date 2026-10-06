// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func testAccCustomPreventListCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_custom_prevent_list" {
			continue
		}
		result, err := c.GetCustomPreventList(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("custom prevent list %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccCustomPreventListResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-pl")
	resourceName := "jamfprotect_custom_prevent_list.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCustomPreventListCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccCustomPreventListResourceConfig(rName, "Team ID", "Test prevent list", teamIDListData),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "prevent_type", "Team ID"),
					resource.TestCheckResourceAttr(resourceName, "description", "Test prevent list"),
					resource.TestCheckResourceAttr(resourceName, "list_data.#", "5"),
					resource.TestCheckResourceAttr(resourceName, "list_data.0", "ABC123DEF4"),
					resource.TestCheckResourceAttr(resourceName, "list_data.1", "DEF456GHI7"),
					resource.TestCheckResourceAttr(resourceName, "list_data.2", "GHI789JKL0"),
					resource.TestCheckResourceAttr(resourceName, "list_data.3", "JKL012MNO3"),
					resource.TestCheckResourceAttr(resourceName, "list_data.4", "MNO345PQR6"),
					resource.TestCheckResourceAttr(resourceName, "entry_count", "5"),
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
				Config: testAccCustomPreventListResourceConfig(rName, "Team ID", "Updated description", teamIDListData),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
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
		CheckDestroy:             testAccCustomPreventListCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomPreventListResourceConfig(rName, "File Hash", "File hash list", fileHashListData),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "prevent_type", "File Hash"),
					resource.TestCheckResourceAttr(resourceName, "list_data.#", "5"),
					resource.TestCheckResourceAttr(resourceName, "list_data.0", fileHashListData[0]),
					resource.TestCheckResourceAttr(resourceName, "entry_count", "5"),
				),
			},
		},
	})
}

// teamIDListData is a set of Apple Team ID shaped entries (10 alphanumeric characters) for TEAMID prevent lists.
var teamIDListData = []string{"ABC123DEF4", "DEF456GHI7", "GHI789JKL0", "JKL012MNO3", "MNO345PQR6"}

// fileHashListData is a set of SHA-256 digests for FILEHASH prevent lists, which the API rejects unless each entry is a 64 character hex digest.
var fileHashListData = []string{
	"462320ac115842cfa2be74f5758d5ebd54fb8b0f2869cfbd563015be61ffc787",
	"1da053f341d3fd479306c7bc31ef21a651022fc832881e229447a1f212cb12e5",
	"333f58994b8c2403b15cf39db4b672e353a15942febb2acd45127a5351eff16b",
	"d8bc624eb92e98b45d030439f3de684f7811285e608d4b92b0c67c5da231ccfc",
	"3d1f69af560f768a26620285715414ebd4b2690c7d1c094150317172a1187096",
}

func testAccCustomPreventListResourceConfig(name, listType, description string, listData []string) string {
	quoted := make([]string, 0, len(listData))
	for _, entry := range listData {
		quoted = append(quoted, fmt.Sprintf("%q", entry))
	}
	return fmt.Sprintf(`
resource "jamfprotect_custom_prevent_list" "test" {
  name         = %[1]q
  prevent_type = %[2]q
  description  = %[3]q
  list_data    = [%[4]s]
}
`, name, listType, description, strings.Join(quoted, ", "))
}
