// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// consoleAnalyticActions mirrors an analytic whose actions were set outside Terraform.
var consoleAnalyticActions = []jamfprotect.AnalyticAction{
	{Name: "Report", Parameters: "{}"},
	{Name: "SmartGroup", Parameters: `{"id":"old-group"}`},
	{Name: "Webhook", Parameters: `{"url":"https://example.invalid/hook","retries":3}`},
}

// actionSummary flattens analytic action models into comparable name=id/url strings.
func actionSummary(t *testing.T, actions []analyticActionModel) []string {
	t.Helper()
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		entry := a.Name.ValueString()
		if !a.Parameters.IsNull() {
			params := map[string]string{}
			if d := a.Parameters.ElementsAs(context.Background(), &params, false); d.HasError() {
				t.Fatalf("decoding parameters: %s", d.Errors()[0].Detail())
			}
			for _, key := range []string{"id", "url", "retries"} {
				if v, ok := params[key]; ok {
					entry += " " + key + "=" + v
				}
			}
		}
		out = append(out, entry)
	}
	return out
}

// equalStrings reports whether two string slices hold the same values in the same order.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// consolePriorActions returns the console actions as a prior-state list.
func consolePriorActions(t *testing.T) types.List {
	t.Helper()
	var diags diag.Diagnostics
	prior := apiAnalyticActionsToList(consoleAnalyticActions, &diags)
	if diags.HasError() {
		t.Fatalf("apiAnalyticActionsToList: %s", diags.Errors()[0].Detail())
	}
	return prior
}

func TestApiAnalyticActionsToList_PreservesOrderAndParameters(t *testing.T) {
	t.Parallel()

	prior := consolePriorActions(t)
	var actions []analyticActionModel
	if d := prior.ElementsAs(context.Background(), &actions, false); d.HasError() {
		t.Fatalf("ElementsAs: %s", d.Errors()[0].Detail())
	}

	want := []string{"Report", "SmartGroup id=old-group", "Webhook url=https://example.invalid/hook retries=3"}
	if got := actionSummary(t, actions); !equalStrings(got, want) {
		t.Errorf("expected %v, got %v", want, got)
	}
	if !actions[0].Parameters.IsNull() {
		t.Errorf("expected null parameters for {}, got %v", actions[0].Parameters)
	}
}

func TestApiAnalyticActionsToList_Empty(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := apiAnalyticActionsToList(nil, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}
	if got.IsNull() || len(got.Elements()) != 0 {
		t.Errorf("expected an empty list, got %v", got)
	}
}

func TestAnalyticActionParametersToMap_InvalidJSON(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	if _, ok := analyticActionParametersToMap("not json", &diags); ok || !diags.HasError() {
		t.Fatal("expected a diagnostic for invalid parameters JSON")
	}
}

func TestMergeSmartGroupAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		add        bool
		identifier types.String
		want       []string
	}{
		{"replaced in place", true, types.StringValue("new-group"), []string{"Report", "SmartGroup id=new-group", "Webhook url=https://example.invalid/hook retries=3"}},
		{"removed when disabled", false, types.StringNull(), []string{"Report", "Webhook url=https://example.invalid/hook retries=3"}},
		{"no identifier", true, types.StringNull(), []string{"Report", "SmartGroup", "Webhook url=https://example.invalid/hook retries=3"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			got := mergeSmartGroupAction(context.Background(), consolePriorActions(t), smartGroupAction(types.BoolValue(tt.add), tt.identifier), &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
			}
			if summary := actionSummary(t, got); !equalStrings(summary, tt.want) {
				t.Errorf("expected %v, got %v", tt.want, summary)
			}
		})
	}
}

func TestMergeSmartGroupAction_AppendsWhenAbsent(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	prior := apiAnalyticActionsToList([]jamfprotect.AnalyticAction{{Name: "Report", Parameters: "{}"}}, &diags)
	got := mergeSmartGroupAction(context.Background(), prior, smartGroupAction(types.BoolValue(true), types.StringValue("grp")), &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}
	want := []string{"Report", "SmartGroup id=grp"}
	if summary := actionSummary(t, got); !equalStrings(summary, want) {
		t.Errorf("expected %v, got %v", want, summary)
	}
}

func TestMergeSmartGroupAction_NullPrior(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	null := types.ListNull(types.ObjectType{AttrTypes: analyticActionAttrTypes})

	if got := mergeSmartGroupAction(context.Background(), null, nil, &diags); got == nil || len(got) != 0 {
		t.Errorf("expected an empty non-nil slice, got %v", got)
	}
	got := mergeSmartGroupAction(context.Background(), null, smartGroupAction(types.BoolValue(true), types.StringValue("grp")), &diags)
	if summary := actionSummary(t, got); !equalStrings(summary, []string{"SmartGroup id=grp"}) {
		t.Errorf("expected only the SmartGroup action, got %v", summary)
	}
}
