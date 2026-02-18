// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set_test

import (
	"fmt"
	"testing"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccExceptionSetResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-exception-set")
	resourceName := "jamfprotect_exception_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccExceptionSetResourceConfig(rName, "Test exception set description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test exception set description"),
					resource.TestCheckResourceAttr(resourceName, "exception.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "exception.*", map[string]string{
						"type":            "Platform Binary",
						"value":           "com.example.app",
						"ignore_activity": "Analytics",
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
		Steps: []resource.TestStep{
			{
				Config: testAccExceptionSetResourceConfigWithEsExceptions(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "endpoint_security_exception.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "endpoint_security_exception.*", map[string]string{
						"type":                "Process Path",
						"value":               "/usr/bin/test",
						"ignore_activity":     "TelemetryV2",
						"ignore_list_type":    "sourceIgnore",
						"ignore_list_subtype": "parent",
						"event_type":          "exec",
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
		Steps: []resource.TestStep{
			{
				Config: testAccExceptionSetResourceConfigWithAppSigningInfo(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "exception.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "exception.*", map[string]string{
						"type":            "App Signing Info",
						"app_id":          "com.example.app",
						"team_id":         "ABC123DEF4",
						"ignore_activity": "Analytics",
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

	exception {
		type            = "Platform Binary"
		value           = "com.example.app"
		ignore_activity = "Analytics"
	}
}
`, name, description)
}

func testAccExceptionSetResourceConfigWithEsExceptions(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_exception_set" "test" {
  name        = %[1]q
  description = "Test exception set with ES exceptions"

	endpoint_security_exception {
		type                = "Process Path"
		value               = "/usr/bin/test"
		ignore_activity     = "TelemetryV2"
		ignore_list_type    = "sourceIgnore"
		ignore_list_subtype = "parent"
		event_type          = "exec"
	}
}
`, name)
}

func testAccExceptionSetResourceConfigWithAppSigningInfo(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_exception_set" "test" {
  name        = %[1]q
  description = "Test exception set with app signing info"

	exception {
		type            = "App Signing Info"
		app_id          = "com.example.app"
		team_id         = "ABC123DEF4"
		ignore_activity = "Analytics"
	}
}
`, name)
}
