package role_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

func testAccRoleCheckDestroy(s *terraform.State) error {
	svc := testutil.TestAccService()
	if svc == nil {
		return fmt.Errorf("service not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_role" {
			continue
		}
		result, err := svc.GetRole(context.Background(), rs.Primary.ID)
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
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
				Config: testAccRoleResourceConfig(rName+"-updated", []string{"Analytics", "Analytic Sets", "Computers", "Plans", "Telemetry", "Exception Sets"}, []string{"Analytics", "Analytic Sets", "Computers", "Plans", "Telemetry"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
				),
			},
		},
	})
}

// testAccRoleResourceConfig builds Terraform configuration for a role resource.
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
