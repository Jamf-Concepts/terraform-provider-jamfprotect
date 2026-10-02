// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package role_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func testAccRoleCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_role" {
			continue
		}
		result, err := c.GetRole(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("role %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

// TestAccRoleResource_basic validates create, read, update, and import behavior.
func TestAccRoleResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-role")
	resourceName := "jamfprotect_role.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRoleResourceConfig(rName, []string{"Analytics", "Analytic Sets", "Computers", "Plans", "Telemetry"}, []string{"Analytics", "Analytic Sets", "Computers", "Plans", "Telemetry"}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccRoleResourceConfig(rName+"-updated", []string{"Analytics", "Analytic Sets", "Computers", "Plans", "Telemetry", "Exception Sets"}, []string{"Analytics", "Analytic Sets", "Computers", "Plans", "Telemetry"}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
				),
			},
		},
	})
}

// testAccRoleResourceConfig builds Terraform configuration for a role resource.
// TestAccRoleResource_loneExceptionDrift verifies that an Exception permission
// granted out of band, without Exception Sets, shows as drift and is removed by
// the next apply.
func TestAccRoleResource_loneExceptionDrift(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-role-exc")
	resourceName := "jamfprotect_role.test"
	config := testAccRoleResourceConfig(rName, []string{"Plans"}, []string{"Plans"})
	var roleID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.TestCheckResourceAttrWith(resourceName, "id", func(value string) error {
					roleID = value
					return nil
				}),
			},
			{
				PreConfig: func() {
					testAccGrantLoneException(t, roleID, rName)
				},
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: testAccCheckRoleLacksException(&roleID),
			},
		},
	})
}

// TestAccRoleResource_rbacResourceLabels verifies that the Data Loss Prevention
// Policies, Endpoint Security Exceptions, Packages, Unified Logging Filter Sets
// and Uninstaller Tokens permissions can be granted and round-trip with no diff.
func TestAccRoleResource_rbacResourceLabels(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-role-rbac")
	resourceName := "jamfprotect_role.test"
	permissions := []string{"Data Loss Prevention Policies", "Endpoint Security Exceptions", "Packages", "Unified Logging Filter Sets", "Uninstaller Tokens"}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRoleResourceConfig(rName, permissions, permissions),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "read_permissions.#", "5"),
					resource.TestCheckResourceAttr(resourceName, "write_permissions.#", "5"),
					resource.TestCheckTypeSetElemAttr(resourceName, "write_permissions.*", "Unified Logging Filter Sets"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// testAccGrantLoneException adds the Exception permission, without Exception
// Sets, to a role's read and write lists through the SDK.
func testAccGrantLoneException(t *testing.T, roleID, name string) {
	t.Helper()

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}
	if _, err := c.UpdateRole(context.Background(), roleID, jamfprotect.RoleInput{
		Name:           name,
		ReadResources:  []string{"Plan", "Exception"},
		WriteResources: []string{"Plan", "Exception"},
	}); err != nil {
		t.Fatalf("granting Exception out of band: %v", err)
	}
}

// testAccCheckRoleLacksException verifies through the SDK that the role no
// longer holds the Exception permission.
func testAccCheckRoleLacksException(roleID *string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		c := testutil.TestAccClient()
		if c == nil {
			return fmt.Errorf("client not configured")
		}
		role, err := c.GetRole(context.Background(), *roleID)
		if err != nil {
			return fmt.Errorf("reading role %s: %w", *roleID, err)
		}
		if role.Permissions == nil {
			return fmt.Errorf("role %s returned no permissions", *roleID)
		}
		if slices.Contains(role.Permissions.Read, "Exception") || slices.Contains(role.Permissions.Write, "Exception") {
			return fmt.Errorf("role %s still holds Exception: R=%v W=%v", *roleID, role.Permissions.Read, role.Permissions.Write)
		}
		return nil
	}
}

func testAccRoleResourceConfig(name string, readPermissions, writePermissions []string) string {
	return fmt.Sprintf(`
resource "jamfprotect_role" "test" {
  name             = %q
  read_permissions = %s
	write_permissions = %s
}
`, name, formatPermissionList(readPermissions), formatPermissionList(writePermissions))
}

// formatPermissionList formats permissions as a Terraform list.
func formatPermissionList(values []string) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, fmt.Sprintf("%q", value))
	}
	return fmt.Sprintf("[%s]", strings.Join(items, ", "))
}
