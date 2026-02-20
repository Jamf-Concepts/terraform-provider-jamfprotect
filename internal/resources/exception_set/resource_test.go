// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

func testAccExceptionSetCheckDestroy(s *terraform.State) error {
	svc := testutil.TestAccService()
	if svc == nil {
		return fmt.Errorf("service not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_exception_set" {
			continue
		}
		result, err := svc.GetExceptionSet(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("exception set %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccExceptionSetResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-exception-set")
	resourceName := "jamfprotect_exception_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccExceptionSetCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccExceptionSetResourceConfig(rName, "Test exception set description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test exception set description"),
					resource.TestCheckResourceAttr(resourceName, "exceptions.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "exceptions.*", map[string]string{
						"type": "Process Event",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "exceptions.*", map[string]string{
						"rules.0.rule_type": "Platform Binary",
						"rules.0.value":     "com.example.app",
					}),
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
				Config: testAccExceptionSetResourceConfig(rName, "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func TestAccExceptionSetResource_withEsExceptions(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-exception-set")
	resourceName := "jamfprotect_exception_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccExceptionSetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccExceptionSetResourceConfigWithEsExceptions(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "exceptions.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "exceptions.*", map[string]string{
						"type":     "Ignore for Telemetry",
						"sub_type": "Source Parent Process",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "exceptions.*", map[string]string{
						"rules.0.rule_type": "Process Path",
						"rules.0.value":     "/usr/bin/test",
					}),
				),
			},
		},
	})
}

func TestAccExceptionSetResource_withAppSigningInfo(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-exception-set")
	resourceName := "jamfprotect_exception_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccExceptionSetCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccExceptionSetResourceConfigWithAppSigningInfo(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "exceptions.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "exceptions.*", map[string]string{
						"type": "Process Event",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "exceptions.*", map[string]string{
						"rules.0.rule_type": "App Signing Info",
						"rules.0.app_id":    "com.example.app",
						"rules.0.team_id":   "ABC123DEF4",
					}),
				),
			},
		},
	})
}

func testAccExceptionSetResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_exception_set" "test" {
  name        = %[1]q
  description = %[2]q

	exceptions = [
		{
			type = "Process Event"
			rules = [
				{
					rule_type = "Platform Binary"
					value     = "com.example.app"
				},
			]
		},
	]
}
`, name, description)
}

func testAccExceptionSetResourceConfigWithEsExceptions(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_exception_set" "test" {
  name        = %[1]q
  description = "Test exception set with ES exceptions"

	exceptions = [
		{
			type     = "Ignore for Telemetry"
			sub_type = "Source Parent Process"
			rules = [
				{
					rule_type = "Process Path"
					value     = "/usr/bin/test"
				},
			]
		},
	]
}
`, name)
}

func testAccExceptionSetResourceConfigWithAppSigningInfo(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_exception_set" "test" {
  name        = %[1]q
  description = "Test exception set with app signing info"

	exceptions = [
		{
			type = "Process Event"
			rules = [
				{
					rule_type = "App Signing Info"
					app_id    = "com.example.app"
					team_id   = "ABC123DEF4"
				},
			]
		},
	]
}
`, name)
}
