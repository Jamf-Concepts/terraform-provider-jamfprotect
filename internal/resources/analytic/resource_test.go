// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func testAccAnalyticCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_analytic" {
			continue
		}
		result, err := c.GetAnalytic(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("analytic %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccAnalyticResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccAnalyticCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccAnalyticResourceConfig(rName, "Test analytic description"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test analytic description"),
					resource.TestCheckResourceAttr(resourceName, "sensor_type", "File System Event"),
					resource.TestCheckResourceAttr(resourceName, "severity", "Informational"),
					resource.TestCheckResourceAttr(resourceName, "level", "0"),
					resource.TestCheckResourceAttr(resourceName, "tags.#", "5"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "alpha"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "beta"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "gamma"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "delta"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "terraform-test"),
					resource.TestCheckResourceAttr(resourceName, "categories.#", "5"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "DefenseEvasion"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "Execution"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "Persistence"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "PrivilegeEscalation"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "Testing"),
					resource.TestCheckResourceAttr(resourceName, "snapshot_files.#", "5"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/a.log"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/b.log"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/c.log"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/d.log"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/e.log"),
					resource.TestCheckResourceAttr(resourceName, "add_to_jamf_pro_smart_group", "false"),
					resource.TestCheckResourceAttr(resourceName, "context_item.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
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
				Config: testAccAnalyticResourceConfig(rName, "Updated description"),
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

func TestAccAnalyticResource_withSmartGroup(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccAnalyticCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAnalyticResourceConfigWithSmartGroup(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "add_to_jamf_pro_smart_group", "true"),
					resource.TestCheckResourceAttr(resourceName, "jamf_pro_smart_group_identifier", "smartgroup"),
					resource.TestCheckResourceAttr(resourceName, "context_item.#", "5"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_alpha",
						"type": "String",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_beta",
						"type": "String",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_gamma",
						"type": "String",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_delta",
						"type": "String",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_epsilon",
						"type": "String",
					}),
				),
			},
		},
	})
}

func testAccAnalyticResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
	sensor_type  = "File System Event"
  description = %[2]q
	filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["alpha", "beta", "gamma", "delta", "terraform-test"]
  categories     = ["DefenseEvasion", "Execution", "Persistence", "PrivilegeEscalation", "Testing"]
  snapshot_files = ["/tmp/a.log", "/tmp/b.log", "/tmp/c.log", "/tmp/d.log", "/tmp/e.log"]

	add_to_jamf_pro_smart_group = false
	context_item                 = []
}
`, name, description)
}

func testAccAnalyticResourceConfigWithSmartGroup(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
	sensor_type  = "File System Event"
	description = "Analytic with Smart Group"
	filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Low"

  tags           = ["alpha", "beta", "gamma", "delta", "terraform-test"]
  categories     = ["DefenseEvasion", "Execution", "Persistence", "PrivilegeEscalation", "Testing"]
  snapshot_files = ["/tmp/a.log", "/tmp/b.log", "/tmp/c.log", "/tmp/d.log", "/tmp/e.log"]

	add_to_jamf_pro_smart_group   = true
	jamf_pro_smart_group_identifier = "smartgroup"

	context_item = [
		{
			name        = "context_alpha"
			type        = "String"
			expressions = [""]
		},
		{
			name        = "context_beta"
			type        = "String"
			expressions = [""]
		},
		{
			name        = "context_gamma"
			type        = "String"
			expressions = [""]
		},
		{
			name        = "context_delta"
			type        = "String"
			expressions = [""]
		},
		{
			name        = "context_epsilon"
			type        = "String"
			expressions = [""]
		},
	]
}
`, name)
}

// testAccAnalyticBackslashFilter holds a single backslash regex escape and a doubled
// backslash NSPredicate escape, both of which must round-trip unchanged.
const testAccAnalyticBackslashFilter = `$event.path MATCHES "^/private/tmp/.*\.sh$" OR $event.path MATCHES "^/private/tmp/[\\w_\\-]+\\.plist$"`

// testAccCheckAnalyticFilter verifies the filter stored on the server for the analytic in state.
func testAccCheckAnalyticFilter(resourceName, want string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		c := testutil.TestAccClient()
		if c == nil {
			return fmt.Errorf("client not configured")
		}
		a, err := c.GetAnalytic(context.Background(), rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("reading analytic %s: %w", rs.Primary.ID, err)
		}
		if a == nil {
			return fmt.Errorf("analytic %s not found", rs.Primary.ID)
		}
		if a.Filter != want {
			return fmt.Errorf("server filter: expected %q, got %q", want, a.Filter)
		}
		return nil
	}
}

func TestAccAnalyticResource_filterBackslashes(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccAnalyticCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAnalyticResourceConfigWithFilter(rName, testAccAnalyticBackslashFilter),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "filter", testAccAnalyticBackslashFilter),
					testAccCheckAnalyticFilter(resourceName, testAccAnalyticBackslashFilter),
				),
			},
		},
	})
}

func testAccAnalyticResourceConfigWithFilter(name, filter string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
  sensor_type = "File System Event"
  description = "Analytic with backslashes in its filter"
  filter      = %[2]q
  level       = 0
  severity    = "Informational"

  tags           = ["terraform-test"]
  categories     = ["Testing"]
  snapshot_files = []

  add_to_jamf_pro_smart_group = false
  context_item                = []
}
`, name, filter)
}

// testAccConsoleAnalyticActions are actions an analytic can carry when it is edited outside
// Terraform; only the SmartGroup entry maps to resource attributes.
var testAccConsoleAnalyticActions = []jamfprotect.AnalyticActionInput{
	{Name: "Report", Parameters: "{}"},
	{Name: "SmartGroup", Parameters: `{"id":"tf-acc-group"}`},
	{Name: "Webhook", Parameters: `{"url":"https://example.invalid/hook"}`},
}

// testAccCreateAnalyticWithConsoleActions creates a custom analytic through the SDK carrying
// testAccConsoleAnalyticActions and removes it when the test ends.
func testAccCreateAnalyticWithConsoleActions(t *testing.T, c *jamfprotect.Client, name string) string {
	t.Helper()
	created, err := c.CreateAnalytic(context.Background(), jamfprotect.AnalyticInput{
		Name:            name,
		InputType:       "GPFSEvent",
		Description:     "Analytic with console actions",
		Filter:          "( $event.type == Filter )",
		Level:           0,
		Severity:        "Informational",
		Tags:            []string{"terraform-test"},
		Categories:      []string{"Testing"},
		SnapshotFiles:   []string{},
		Context:         []jamfprotect.AnalyticContextInput{},
		AnalyticActions: testAccConsoleAnalyticActions,
	})
	if err != nil {
		t.Fatalf("creating analytic: %s", err)
	}
	t.Cleanup(func() {
		if a, err := c.GetAnalytic(context.Background(), created.UUID); err == nil && a != nil {
			if err := c.DeleteAnalytic(context.Background(), created.UUID); err != nil {
				t.Errorf("deleting analytic %s: %s", created.UUID, err)
			}
		}
	})
	return created.UUID
}

// testAccCheckAnalyticActionNames verifies the action names stored on the server, in order.
func testAccCheckAnalyticActionNames(c *jamfprotect.Client, uuid string, want ...string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		a, err := c.GetAnalytic(context.Background(), uuid)
		if err != nil {
			return fmt.Errorf("reading analytic %s: %w", uuid, err)
		}
		if a == nil {
			return fmt.Errorf("analytic %s not found", uuid)
		}
		got := make([]string, 0, len(a.AnalyticActions))
		for _, action := range a.AnalyticActions {
			got = append(got, action.Name)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			return fmt.Errorf("server analyticActions: expected %v, got %v", want, got)
		}
		return nil
	}
}

func TestAccAnalyticResource_preservesConsoleActions(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test; set TF_ACC=1 to run")
	}
	testutil.TestAccPreCheck(t)

	c := testutil.TestAccClient()
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	uuid := testAccCreateAnalyticWithConsoleActions(t, c, rName)
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccAnalyticCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:             testAccAnalyticResourceConfigWithConsoleActions(rName, "Analytic with console actions"),
				ResourceName:       resourceName,
				ImportState:        true,
				ImportStateId:      uuid,
				ImportStatePersist: true,
			},
			{
				Config: testAccAnalyticResourceConfigWithConsoleActions(rName, "Description changed by Terraform"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue(resourceName, tfjsonpath.New("analytic_actions"), knownvalue.ListExact([]knownvalue.Check{
							knownvalue.ObjectPartial(map[string]knownvalue.Check{"name": knownvalue.StringExact("Report")}),
							knownvalue.ObjectPartial(map[string]knownvalue.Check{"name": knownvalue.StringExact("SmartGroup")}),
							knownvalue.ObjectPartial(map[string]knownvalue.Check{"name": knownvalue.StringExact("Webhook")}),
						})),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Description changed by Terraform"),
					resource.TestCheckResourceAttr(resourceName, "analytic_actions.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "analytic_actions.2.parameters.url", "https://example.invalid/hook"),
					testAccCheckAnalyticActionNames(c, uuid, "Report", "SmartGroup", "Webhook"),
				),
			},
		},
	})
}

func testAccAnalyticResourceConfigWithConsoleActions(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
  sensor_type = "File System Event"
  description = %[2]q
  filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["terraform-test"]
  categories     = ["Testing"]
  snapshot_files = []

  add_to_jamf_pro_smart_group     = true
  jamf_pro_smart_group_identifier = "tf-acc-group"
  context_item                    = []
}
`, name, description)
}
