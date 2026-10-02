// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"
	"slices"
	"testing"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// TestAPIToState_PartialCategoryAndUnmodelledEvents verifies a partial category reads false and unmodelled events are kept.
func TestAPIToState_PartialCategoryAndUnmodelledEvents(t *testing.T) {
	api := jamfprotect.TelemetryV2{
		ID:     "1",
		Name:   "partial",
		Events: append([]string{"login_login", "xpc_connect", "fork"}, logSystemEvents...),
	}

	var data TelemetryV2ResourceModel
	(&TelemetryV2Resource{}).apiToState(context.Background(), &data, api)

	if data.LogAccessAuth.ValueBool() {
		t.Error("expected log_access_and_authentication to be false for a partial category")
	}
	if !data.LogSystem.ValueBool() {
		t.Error("expected log_system to be true for a complete category")
	}

	var diags diag.Diagnostics
	var got []string
	diags.Append(data.AdditionalEvents.ElementsAs(context.Background(), &got, false)...)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	slices.Sort(got)
	if expected := []string{"fork", "xpc_connect"}; !slices.Equal(got, expected) {
		t.Errorf("expected additional_events %v, got %v", expected, got)
	}
}

// TestAPIToState_NoUnmodelledEvents verifies additional_events is an empty, non-null set when every event is categorised.
func TestAPIToState_NoUnmodelledEvents(t *testing.T) {
	var data TelemetryV2ResourceModel
	(&TelemetryV2Resource{}).apiToState(context.Background(), &data, jamfprotect.TelemetryV2{ID: "1", Events: logNetworkEvents})

	if data.AdditionalEvents.IsNull() || data.AdditionalEvents.IsUnknown() {
		t.Fatal("expected a known additional_events set")
	}
	if n := len(data.AdditionalEvents.Elements()); n != 0 {
		t.Errorf("expected no additional events, got %d", n)
	}
}
