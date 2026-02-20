// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic_set_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

func testAccAnalyticSetCheckDestroy(s *terraform.State) error {
	svc := testutil.TestAccService()
	if svc == nil {
		return fmt.Errorf("service not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_analytic_set" {
			continue
		}
		result, err := svc.GetAnalyticSet(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("analytic set %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccAnalyticSetResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic-set")
	resourceName := "jamfprotect_analytic_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccAnalyticSetCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccAnalyticSetResourceConfig(rName, "Test analytic set description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test analytic set description"),
					resource.TestCheckResourceAttr(resourceName, "analytics.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
					resource.TestCheckResourceAttrSet(resourceName, "managed"),
				),
			},
			// ImportState testing.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing.
			{
				Config: testAccAnalyticSetResourceConfig(rName, "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func testAccAnalyticSetResourceConfig(name, description string) string {
	return fmt.Sprintf(`
# First create an analytic to reference
resource "jamfprotect_analytic" "test" {
  name        = "%[1]s-analytic"
	sensor_type = "File System Event"
  description = "Test analytic for set"
	filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["terraform-test"]
  categories     = ["Testing"]
  snapshot_files = []

	add_to_jamf_pro_smart_group = false
	context_item                = []
}

resource "jamfprotect_analytic_set" "test" {
  name        = %[1]q
  description = %[2]q
  analytics   = [jamfprotect_analytic.test.id]
}
`, name, description)
}

func TestAccAnalyticSetResource_withTypes(t *testing.T) {
	t.Skip("types are now configured automatically and are no longer part of the resource schema")
}
