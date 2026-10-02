// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func testAccActionConfigCheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_action_configuration" {
			continue
		}
		result, err := c.GetActionConfig(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("action configuration %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccActionConfigResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ac")
	resourceName := "jamfprotect_action_configuration.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccActionConfigCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccActionConfigResourceConfig(rName, "Test action config"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test action config"),
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
				Config: testAccActionConfigResourceConfig(rName, "Updated description"),
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

func testAccActionConfigResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_configuration" "test" {
  name        = %[1]q
  description = %[2]q

	alert_data_collection = {
		binary_included_data_attributes                     = ["Sha1", "Sha256", "Signing Information"]
		synthetic_click_event_included_data_attributes      = ["Process", "User", "Group"]
		download_event_included_data_attributes             = ["File"]
		file_included_data_attributes                       = ["Sha1", "Sha256", "User", "Group"]
		file_system_event_included_data_attributes          = ["File", "Process", "User", "Group"]
		group_included_data_attributes                      = ["Name"]
		process_event_included_data_attributes              = ["Process"]
		process_included_data_attributes                    = ["Args", "Binary", "User", "Group"]
		screenshot_event_included_data_attributes           = ["File"]
		user_included_data_attributes                       = ["Name"]
		gatekeeper_event_included_data_attributes           = ["Blocked Process", "Blocked Binary"]
		keylog_register_event_included_data_attributes      = ["Source Process", "Destination Process"]
	}
}
`, name, description)
}

// TestAccActionConfigResource_httpHeaderWriteOnly verifies that a write-only
// HTTP header value reaches Jamf Protect, stays out of state, and rotates when
// value_wo_version changes.
func TestAccActionConfigResource_httpHeaderWriteOnly(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ac")
	resourceName := "jamfprotect_action_configuration.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		CheckDestroy:             testAccActionConfigCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccActionConfigResourceHTTPHeaderWriteOnlyConfig(rName, "Bearer tf-acc-one", "1"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "http_endpoints.0.headers.0.header", "Authorization"),
					resource.TestCheckNoResourceAttr(resourceName, "http_endpoints.0.headers.0.value"),
					resource.TestCheckNoResourceAttr(resourceName, "http_endpoints.0.headers.0.value_wo"),
					resource.TestCheckResourceAttr(resourceName, "http_endpoints.0.headers.0.value_wo_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "http_endpoints.0.headers.1.value", "application/json"),
					testAccCheckActionConfigHTTPHeaderValue(resourceName, "Authorization", "Bearer tf-acc-one"),
				),
			},
			{
				Config: testAccActionConfigResourceHTTPHeaderWriteOnlyConfig(rName, "Bearer tf-acc-two", "2"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(resourceName, "http_endpoints.0.headers.0.value"),
					resource.TestCheckResourceAttr(resourceName, "http_endpoints.0.headers.0.value_wo_version", "2"),
					testAccCheckActionConfigHTTPHeaderValue(resourceName, "Authorization", "Bearer tf-acc-two"),
				),
			},
			{
				ResourceName:     resourceName,
				ImportState:      true,
				ImportStateCheck: testAccCheckImportedHeaderValuesNull,
			},
		},
	})
}

// testAccCheckImportedHeaderValuesNull checks that an import stores no HTTP
// header value, so a write-only secret never reaches state.
func testAccCheckImportedHeaderValuesNull(states []*terraform.InstanceState) error {
	if len(states) != 1 {
		return fmt.Errorf("expected 1 imported state, got %d", len(states))
	}
	attrs := states[0].Attributes
	if attrs["http_endpoints.0.headers.#"] != "2" {
		return fmt.Errorf("expected 2 imported headers, got %q", attrs["http_endpoints.0.headers.#"])
	}
	for _, key := range []string{"http_endpoints.0.headers.0.value", "http_endpoints.0.headers.1.value"} {
		if value, ok := attrs[key]; ok && value != "" {
			return fmt.Errorf("%s is set in imported state", key)
		}
	}
	return nil
}

// testAccCheckActionConfigHTTPHeaderValue checks the value Jamf Protect holds
// for an HTTP endpoint header, which a write-only value never exposes in state.
func testAccCheckActionConfigHTTPHeaderValue(resourceName, header, want string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		c := testutil.TestAccClient()
		if c == nil {
			return fmt.Errorf("client not configured")
		}
		result, err := c.GetActionConfig(context.Background(), rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("reading action configuration %s: %w", rs.Primary.ID, err)
		}
		for _, client := range result.Clients {
			if client.Type != "Http" {
				continue
			}
			for _, h := range client.Params.Headers {
				if h.Header == header {
					if h.Value != want {
						return fmt.Errorf("header %s has an unexpected value in Jamf Protect", header)
					}
					return nil
				}
			}
		}
		return fmt.Errorf("header %s not found on any HTTP endpoint", header)
	}
}

func testAccActionConfigResourceHTTPHeaderWriteOnlyConfig(name, token, version string) string {
	return fmt.Sprintf(`
resource "jamfprotect_action_configuration" "test" {
  name        = %[1]q
  description = "Write-only HTTP header"

	alert_data_collection = {
		binary_included_data_attributes                     = ["Sha256"]
		synthetic_click_event_included_data_attributes      = ["Process"]
		download_event_included_data_attributes             = ["File"]
		file_included_data_attributes                       = ["Sha256"]
		file_system_event_included_data_attributes          = ["File"]
		group_included_data_attributes                      = ["Name"]
		process_event_included_data_attributes              = ["Process"]
		process_included_data_attributes                    = ["Binary"]
		screenshot_event_included_data_attributes           = ["File"]
		user_included_data_attributes                       = ["Name"]
		gatekeeper_event_included_data_attributes           = ["Blocked Process"]
		keylog_register_event_included_data_attributes      = ["Source Process"]
	}

	http_endpoints = [
		{
			collect_alerts          = ["high"]
			collect_logs            = []
			events_per_batch        = 100
			batching_window_seconds = 30
			event_delimiter         = "\n"
			max_batch_size_bytes    = 1048576
			url                     = "https://tf-acc.example.com/hook"
			method                  = "POST"
			headers = [
				{
					header           = "Authorization"
					value_wo         = %[2]q
					value_wo_version = %[3]q
				},
				{
					header = "Content-Type"
					value  = "application/json"
				},
			]
		},
	]
}
`, name, token, version)
}

// TestAccActionConfigResource_importRejectsSecondJamfCloudEndpoint verifies that
// importing an action configuration with two JamfCloud clients fails, rather
// than importing the first one and dropping the second. The API accepts the
// second client, but jamf_protect_cloud_endpoint holds only one.
func TestAccActionConfigResource_importRejectsSecondJamfCloudEndpoint(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ac-dup")
	var configID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccActionConfigCheckDestroy,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					configID = testAccCreateActionConfigWithTwoJamfCloudClients(t, rName)
				},
				Config:       testAccActionConfigResourceConfig(rName, "duplicate JamfCloud clients"),
				ResourceName: "jamfprotect_action_configuration.test",
				ImportState:  true,
				ImportStateIdFunc: func(*terraform.State) (string, error) {
					return configID, nil
				},
				ExpectError: regexp.MustCompile(`more than one JamfCloud endpoint`),
			},
		},
	})
}

// testAccCreateActionConfigWithTwoJamfCloudClients creates, through the SDK, an
// action configuration carrying two JamfCloud clients, and deletes it when the
// test ends.
func testAccCreateActionConfigWithTwoJamfCloudClients(t *testing.T, name string) string {
	t.Helper()

	c := testutil.TestAccClient()
	if c == nil {
		t.Fatal("client not configured")
	}

	eventTypes := map[string]any{}
	for _, eventType := range []string{"binary", "clickEvent", "downloadEvent", "file", "fsEvent", "gkEvent", "group", "keylogRegisterEvent", "mrtEvent", "procEvent", "process", "screenshotEvent", "usbEvent", "user"} {
		eventTypes[eventType] = map[string]any{"attrs": []string{}, "related": []string{}}
	}
	jamfCloudClient := func(reports ...string) map[string]any {
		return map[string]any{
			"type":             "JamfCloud",
			"supportedReports": reports,
			"batchConfig":      map[string]any{"sizeIndex": 1, "windowInSeconds": 0},
			"params":           "{}",
		}
	}

	created, err := c.CreateActionConfig(context.Background(), jamfprotect.ActionConfigInput{
		Name:        name,
		Description: "duplicate JamfCloud clients",
		Clients:     []map[string]any{jamfCloudClient("AlertHigh"), jamfCloudClient("AlertLow", "Telemetry")},
		AlertConfig: map[string]any{"data": eventTypes},
	})
	if err != nil {
		t.Fatalf("creating action configuration out of band: %v", err)
	}
	t.Cleanup(func() {
		if err := c.DeleteActionConfig(context.Background(), created.ID); err != nil {
			t.Errorf("deleting action configuration %s: %v", created.ID, err)
		}
	})

	return created.ID
}
