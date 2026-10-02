// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/provider"
)

// TestAccProtoV6ProviderFactories instantiates a provider during acceptance testing.
func TestAccProtoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"jamfprotect": providerserver.NewProtocol6WithError(provider.New("test")()),
	}
}

// TestAccPreCheck verifies required environment variables for acceptance tests.
func TestAccPreCheck(t *testing.T) {
	t.Helper()

	required := []string{"JAMFPROTECT_URL", "JAMFPROTECT_CLIENT_ID", "JAMFPROTECT_CLIENT_SECRET"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			t.Fatalf("environment variable %s must be set for acceptance tests", env)
		}
	}
}

// TestAccClient returns a Client for use in CheckDestroy functions.
// Returns nil if the required environment variables are not set.
func TestAccClient() *jamfprotect.Client {
	url := os.Getenv("JAMFPROTECT_URL")
	clientID := os.Getenv("JAMFPROTECT_CLIENT_ID")
	clientSecret := os.Getenv("JAMFPROTECT_CLIENT_SECRET")
	if url == "" || clientID == "" || clientSecret == "" {
		return nil
	}
	return jamfprotect.NewClient(url, clientID, clientSecret)
}

// PlanUpdateInput returns a PlanInput carrying only the fields updatePlan requires,
// copied from api. Membership fields are left unset so the API keeps them, which lets
// a test change one of them out of band the way an edit in the console would.
func PlanUpdateInput(api jamfprotect.Plan) jamfprotect.PlanInput {
	input := jamfprotect.PlanInput{
		Name:                     api.Name,
		Description:              api.Description,
		AutoUpdate:               api.AutoUpdate,
		ThreatPreventionStrategy: api.ThreatPreventionStrategy,
	}
	if api.ActionConfigs != nil {
		input.ActionConfigs = api.ActionConfigs.ID
	}
	if api.CommsConfig != nil {
		input.CommsConfig = jamfprotect.PlanCommsConfigInput{
			FQDN:     api.CommsConfig.FQDN,
			Protocol: api.CommsConfig.Protocol,
		}
	}
	if api.InfoSync != nil {
		input.InfoSync = jamfprotect.PlanInfoSyncInput{
			Attrs:                api.InfoSync.Attrs,
			InsightsSyncInterval: api.InfoSync.InsightsSyncInterval,
		}
	}
	if api.SignaturesFeedConfig != nil {
		input.SignaturesFeedConfig = jamfprotect.PlanSignaturesFeedConfigInput{
			Mode: api.SignaturesFeedConfig.Mode,
		}
	}
	return input
}

// CaptureAttr stores an attribute value from state for use in a later test step.
func CaptureAttr(resourceName, attr string, target *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		value, ok := rs.Primary.Attributes[attr]
		if !ok {
			return fmt.Errorf("attribute %s not found on %s", attr, resourceName)
		}
		*target = value
		return nil
	}
}
