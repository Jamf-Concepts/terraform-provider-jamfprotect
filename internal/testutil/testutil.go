// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/client"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
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

// TestAccService returns a Service for use in CheckDestroy functions.
// Returns nil if the required environment variables are not set.
func TestAccService() *jamfprotect.Service {
	url := os.Getenv("JAMFPROTECT_URL")
	clientID := os.Getenv("JAMFPROTECT_CLIENT_ID")
	clientSecret := os.Getenv("JAMFPROTECT_CLIENT_SECRET")
	if url == "" || clientID == "" || clientSecret == "" {
		return nil
	}
	return jamfprotect.NewService(client.NewClient(url, clientID, clientSecret))
}
