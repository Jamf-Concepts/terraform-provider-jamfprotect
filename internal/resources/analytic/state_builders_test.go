// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// filterVerbatimCases lists filters whose backslashes must reach state exactly as the API returns them.
var filterVerbatimCases = []struct {
	name   string
	filter string
}{
	{"no backslashes", `$event.type == 0`},
	{"single backslash regex escape", `$event.path MATCHES "^/tmp/.*\.sh$"`},
	{"doubled backslash predicate escape", `$event.path MATCHES "[\\w_\\.\\-]+\\.plist"`},
	{"quadruple backslash", `$event.path == "a\\\\b"`},
}

// TestApplyState_FilterVerbatim verifies the resource stores the API filter without rewriting backslashes.
func TestApplyState_FilterVerbatim(t *testing.T) {
	t.Parallel()

	for _, tt := range filterVerbatimCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var data AnalyticResourceModel
			var diags diag.Diagnostics
			(&AnalyticResource{}).applyState(context.Background(), &data, jamfprotect.Analytic{
				UUID:      "uuid",
				InputType: "GPFSEvent",
				Filter:    tt.filter,
			}, &diags)

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
			}
			if got := data.Filter.ValueString(); got != tt.filter {
				t.Errorf("expected %q, got %q", tt.filter, got)
			}
		})
	}
}

// TestAnalyticAPIToDataSourceItem_FilterVerbatim verifies the data source reports the API filter without rewriting backslashes.
func TestAnalyticAPIToDataSourceItem_FilterVerbatim(t *testing.T) {
	t.Parallel()

	for _, tt := range filterVerbatimCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			item := analyticAPIToDataSourceItem(jamfprotect.Analytic{
				UUID:      "uuid",
				InputType: "GPFSEvent",
				Filter:    tt.filter,
			}, &diags)

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
			}
			if got := item.Filter.ValueString(); got != tt.filter {
				t.Errorf("expected %q, got %q", tt.filter, got)
			}
		})
	}
}
