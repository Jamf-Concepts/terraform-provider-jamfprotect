// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccUnifiedLoggingFilterResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulf")
	resourceName := "jamfprotect_unified_logging_filter.test"
	logLevel := testAccUnifiedLoggingLevel(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccUnifiedLoggingFilterResourceConfig(rName, "Test filter description", true, logLevel),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "uuid"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test filter description"),
					resource.TestCheckResourceAttr(resourceName, "filter", `subsystem == "com.apple.securityd"`),
					resource.TestCheckResourceAttr(resourceName, "level", logLevel),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "tags.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.0", "terraform-test"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
				),
			},
			// ImportState testing.
			{
				ResourceName: resourceName,
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return "", fmt.Errorf("resource not found: %s", resourceName)
					}
					return rs.Primary.Attributes["uuid"], nil
				},
				ImportStateVerify: true,
			},
			// Update: disable the filter.
			{
				Config: testAccUnifiedLoggingFilterResourceConfig(rName, "Updated description", false, logLevel),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
				),
			},
		},
	})
}

func testAccUnifiedLoggingFilterResourceConfig(name, description string, enabled bool, level string) string {
	return fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter" "test" {
  name        = %[1]q
  description = %[2]q
  filter      = "subsystem == \"com.apple.securityd\""
  level       = %[3]q
  enabled     = %[4]t
  tags        = ["terraform-test"]
}
`, name, description, level, enabled)
}

func testAccUnifiedLoggingLevel(t *testing.T) string {
	t.Helper()
	values, ok := testAccEnumValues["UNIFIED_LOGGING_LEVEL"]
	if !ok || len(values) == 0 {
		t.Skip("UNIFIED_LOGGING_LEVEL enum values not available")
	}
	return values[0]
}
