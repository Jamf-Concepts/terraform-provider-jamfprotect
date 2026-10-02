// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

func TestBuildInput_CarriesPriorActions(t *testing.T) {
	t.Parallel()

	data := AnalyticResourceModel{
		Name:                        types.StringValue("a"),
		SensorType:                  types.StringValue("File System Event"),
		Description:                 types.StringValue("changed"),
		Filter:                      types.StringValue("$event.type == 0"),
		Level:                       types.Int64Value(0),
		Severity:                    types.StringValue("Low"),
		Tags:                        types.SetValueMust(types.StringType, []attr.Value{}),
		Categories:                  types.SetValueMust(types.StringType, []attr.Value{}),
		SnapshotFiles:               types.SetValueMust(types.StringType, []attr.Value{}),
		AddToJamfProSmartGroup:      types.BoolValue(true),
		JamfProSmartGroupIdentifier: types.StringValue("old-group"),
		ContextItem:                 types.SetNull(types.ObjectType{AttrTypes: analyticContextAttrTypes}),
	}

	var diags diag.Diagnostics
	input := (&AnalyticResource{}).buildInput(context.Background(), data, consolePriorActions(t), &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}

	want := []jamfprotect.AnalyticActionInput{
		{Name: "Report", Parameters: "{}"},
		{Name: "SmartGroup", Parameters: `{"id":"old-group"}`},
		{Name: "Webhook", Parameters: `{"retries":"3","url":"https://example.invalid/hook"}`},
	}
	if len(input.AnalyticActions) != len(want) {
		t.Fatalf("expected %d actions, got %d: %v", len(want), len(input.AnalyticActions), input.AnalyticActions)
	}
	for i := range want {
		if input.AnalyticActions[i] != want[i] {
			t.Errorf("action %d: expected %+v, got %+v", i, want[i], input.AnalyticActions[i])
		}
	}
}

func TestBuildInput_CreateSendsOnlySmartGroup(t *testing.T) {
	t.Parallel()

	data := AnalyticResourceModel{
		Name:                        types.StringValue("a"),
		SensorType:                  types.StringValue("File System Event"),
		Filter:                      types.StringValue("$event.type == 0"),
		Severity:                    types.StringValue("Low"),
		Tags:                        types.SetValueMust(types.StringType, []attr.Value{}),
		Categories:                  types.SetValueMust(types.StringType, []attr.Value{}),
		SnapshotFiles:               types.SetValueMust(types.StringType, []attr.Value{}),
		AddToJamfProSmartGroup:      types.BoolValue(false),
		JamfProSmartGroupIdentifier: types.StringNull(),
		ContextItem:                 types.SetNull(types.ObjectType{AttrTypes: analyticContextAttrTypes}),
	}

	var diags diag.Diagnostics
	input := (&AnalyticResource{}).buildInput(context.Background(), data, types.ListNull(types.ObjectType{AttrTypes: analyticActionAttrTypes}), &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}
	if input.AnalyticActions == nil || len(input.AnalyticActions) != 0 {
		t.Errorf("expected an empty non-nil action list, got %v", input.AnalyticActions)
	}
}
