// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

func TestApiToState_EmptyMembershipFollowsPriorValue(t *testing.T) {
	t.Parallel()

	empty := types.SetValueMust(types.StringType, []attr.Value{})
	tests := []struct {
		name     string
		prior    types.Set
		expected types.Set
	}{
		{name: "null prior stays null", prior: types.SetNull(types.StringType), expected: types.SetNull(types.StringType)},
		{name: "empty prior stays empty", prior: empty, expected: empty},
		{name: "unknown prior becomes empty", prior: types.SetUnknown(types.StringType), expected: empty},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := PlanResourceModel{ExceptionSets: tt.prior, AnalyticSets: tt.prior}
			var diags diag.Diagnostics
			(&PlanResource{}).apiToState(context.Background(), &data, jamfprotect.Plan{ID: "1"}, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if !data.ExceptionSets.Equal(tt.expected) {
				t.Errorf("ExceptionSets = %v, want %v", data.ExceptionSets, tt.expected)
			}
			if !data.AnalyticSets.Equal(tt.expected) {
				t.Errorf("AnalyticSets = %v, want %v", data.AnalyticSets, tt.expected)
			}
		})
	}
}

func TestApiToState_MembershipReadFromAPI(t *testing.T) {
	t.Parallel()

	api := jamfprotect.Plan{
		ID:            "1",
		ExceptionSets: []jamfprotect.PlanExceptionSet{{UUID: testCustomUUID}},
		AnalyticSets: []jamfprotect.PlanAnalyticSet{
			{Type: "Report", AnalyticSet: jamfprotect.PlanAnalyticSetRef{UUID: testCustomUUID, Name: "Custom"}},
			{Type: "Prevent", AnalyticSet: jamfprotect.PlanAnalyticSetRef{UUID: testATCUUID, Name: advancedThreatControlsName, Managed: true}},
		},
	}
	data := PlanResourceModel{ExceptionSets: types.SetNull(types.StringType), AnalyticSets: types.SetNull(types.StringType)}
	var diags diag.Diagnostics
	(&PlanResource{}).apiToState(context.Background(), &data, api, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	want := types.SetValueMust(types.StringType, []attr.Value{types.StringValue(testCustomUUID)})
	if !data.ExceptionSets.Equal(want) {
		t.Errorf("ExceptionSets = %v, want %v", data.ExceptionSets, want)
	}
	if !data.AnalyticSets.Equal(want) {
		t.Errorf("AnalyticSets = %v, want %v", data.AnalyticSets, want)
	}
	if got := data.AdvancedThreatControls.ValueString(); got != "Block and report" {
		t.Errorf("AdvancedThreatControls = %q, want %q", got, "Block and report")
	}
}
