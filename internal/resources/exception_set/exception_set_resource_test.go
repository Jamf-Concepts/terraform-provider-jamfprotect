// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exceptionset_test

import (
	"fmt"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
	"testing"

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
					resource.TestCheckResourceAttr(resourceName, "exceptions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "exceptions.0.type", "SHA256Hash"),
					resource.TestCheckResourceAttr(resourceName, "exceptions.0.value", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
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
					resource.TestCheckResourceAttr(resourceName, "es_exceptions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "es_exceptions.0.type", "ProcessPath"),
					resource.TestCheckResourceAttr(resourceName, "es_exceptions.0.value", "/usr/bin/test"),
					resource.TestCheckResourceAttr(resourceName, "es_exceptions.0.ignore_list_type", "ALLOW"),
					resource.TestCheckResourceAttr(resourceName, "es_exceptions.0.event_type", "ES_EVENT_TYPE_AUTH_EXEC"),
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
					resource.TestCheckResourceAttr(resourceName, "exceptions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "exceptions.0.type", "SigningId"),
					resource.TestCheckResourceAttr(resourceName, "exceptions.0.value", "com.example.app"),
					resource.TestCheckResourceAttr(resourceName, "exceptions.0.app_signing_info.app_id", "com.example.app"),
					resource.TestCheckResourceAttr(resourceName, "exceptions.0.app_signing_info.team_id", "ABC123DEF4"),
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
      type            = "SHA256Hash"
      value           = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      ignore_activity = false
    }
  ]
}
`, name, description)
}

func testAccExceptionSetResourceConfigWithEsExceptions(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_exception_set" "test" {
  name        = %[1]q
  description = "Test exception set with ES exceptions"

  exceptions = []

  es_exceptions = [
    {
      type                = "ProcessPath"
      value               = "/usr/bin/test"
      ignore_activity     = false
      ignore_list_type    = "ALLOW"
      ignore_list_subtype = "NONE"
      event_type          = "ES_EVENT_TYPE_AUTH_EXEC"
    }
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
      type  = "SigningId"
      value = "com.example.app"
      app_signing_info = {
        app_id  = "com.example.app"
        team_id = "ABC123DEF4"
      }
      ignore_activity = false
    }
  ]
}
`, name)
}
