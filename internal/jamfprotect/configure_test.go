// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/client"
)

func TestConfigureService_NilProviderData(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	svc := ConfigureService(nil, &diags)

	if svc != nil {
		t.Error("expected nil service for nil provider data")
	}
	if diags.HasError() {
		t.Errorf("expected no diagnostics, got %v", diags)
	}
}

func TestConfigureService_ValidClient(t *testing.T) {
	t.Parallel()

	c := client.NewClient("https://example.com", "cid", "csecret")
	var diags diag.Diagnostics
	svc := ConfigureService(c, &diags)

	if svc == nil {
		t.Error("expected non-nil service")
	}
	if diags.HasError() {
		t.Errorf("expected no diagnostics, got %v", diags)
	}
}

func TestConfigureService_WrongType(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	svc := ConfigureService("not a client", &diags)

	if svc != nil {
		t.Error("expected nil service for wrong type")
	}
	if !diags.HasError() {
		t.Error("expected error diagnostic for wrong type")
	}
	found := false
	for _, d := range diags {
		if d.Summary() == "Unexpected Configure Type" {
			found = true
		}
	}
	if !found {
		t.Error("expected diagnostic with summary 'Unexpected Configure Type'")
	}
}
