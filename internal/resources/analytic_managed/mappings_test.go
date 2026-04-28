// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

func TestMapSensorTypeAPIToUI_KnownValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"GPFSEvent", "File System Event"},
		{"GPDownloadEvent", "Download Event"},
		{"GPProcessEvent", "Process Event"},
		{"GPScreenshotEvent", "Screenshot Event"},
		{"GPKeylogRegisterEvent", "Keylog Register Event"},
		{"GPClickEvent", "Synthetic Click Event"},
		{"GPMRTEvent", "Malware Removal Tool Event"},
		{"GPUSBEvent", "USB Event"},
		{"GPGatekeeperEvent", "Gatekeeper Event"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			got := mapSensorTypeAPIToUI(tt.input)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// TestMapSensorTypeAPIToUI_UnknownPassesThrough verifies that an unrecognized API
// value is returned unchanged. Jamf-managed analytics may use sensor types not in
// the custom-analytic schema; we surface the raw API value rather than erroring.
func TestMapSensorTypeAPIToUI_UnknownPassesThrough(t *testing.T) {
	t.Parallel()

	got := mapSensorTypeAPIToUI("GPSomeNewEvent")
	if got != "GPSomeNewEvent" {
		t.Errorf("expected pass-through value, got %q", got)
	}
}

func TestNormalizeFilterValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"plain", "plain text", "plain text"},
		{"single backslash unchanged", `path\to\file`, `path\to\file`},
		{"double backslash collapsed", `path\\to\\file`, `path\to\file`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeFilterValue(tt.input)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestApiActionsToSet_EmptyAndNil(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		api  []jamfprotect.AnalyticAction
	}{
		{"nil slice", nil},
		{"empty slice", []jamfprotect.AnalyticAction{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			got := apiActionsToSet(tt.api, &diags)

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
			}
			if got.IsNull() {
				t.Fatal("expected empty (non-null) set, got null")
			}
			if len(got.Elements()) != 0 {
				t.Errorf("expected 0 elements, got %d", len(got.Elements()))
			}
		})
	}
}

func TestApiActionsToSet_ActionWithParameters(t *testing.T) {
	t.Parallel()

	api := []jamfprotect.AnalyticAction{
		{Name: "SmartGroup", Parameters: `{"id":"smartgroup"}`},
	}

	var diags diag.Diagnostics
	got := apiActionsToSet(api, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}
	if got.IsNull() {
		t.Fatal("expected non-null set")
	}

	elems := got.Elements()
	if len(elems) != 1 {
		t.Fatalf("expected 1 element, got %d", len(elems))
	}

	obj, ok := elems[0].(types.Object)
	if !ok {
		t.Fatalf("expected types.Object element, got %T", elems[0])
	}

	attrs := obj.Attributes()
	name, _ := attrs["name"].(types.String)
	if name.ValueString() != "SmartGroup" {
		t.Errorf("expected name=SmartGroup, got %q", name.ValueString())
	}

	params, _ := attrs["parameters"].(types.Map)
	if params.IsNull() {
		t.Fatal("expected non-null parameters map")
	}
	paramElems := params.Elements()
	idVal, _ := paramElems["id"].(types.String)
	if idVal.ValueString() != "smartgroup" {
		t.Errorf("expected parameters.id=smartgroup, got %q", idVal.ValueString())
	}
}

func TestApiActionsToSet_ActionWithoutParameters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params string
	}{
		{"empty string params", ""},
		{"empty json object params", "{}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			api := []jamfprotect.AnalyticAction{
				{Name: "Log", Parameters: tt.params},
			}

			var diags diag.Diagnostics
			got := apiActionsToSet(api, &diags)

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
			}

			elems := got.Elements()
			if len(elems) != 1 {
				t.Fatalf("expected 1 element, got %d", len(elems))
			}

			obj := elems[0].(types.Object)
			params := obj.Attributes()["parameters"].(types.Map)
			if !params.IsNull() {
				t.Errorf("expected null parameters map, got %v", params)
			}
		})
	}
}

func TestApiActionsToSet_BadJSONReportsDiagnostic(t *testing.T) {
	t.Parallel()

	api := []jamfprotect.AnalyticAction{
		{Name: "BadAction", Parameters: `not-valid-json`},
	}

	var diags diag.Diagnostics
	got := apiActionsToSet(api, &diags)

	if !diags.HasError() {
		t.Fatal("expected diagnostic error for invalid parameters JSON")
	}
	if !got.IsNull() {
		t.Error("expected null set when JSON parse fails")
	}
}

func TestBuildInternalInput_AllNullProducesEmptyInput(t *testing.T) {
	t.Parallel()

	r := &AnalyticManagedResource{}
	data := AnalyticManagedResourceModel{
		TenantSeverity: types.StringNull(),
		TenantActions:  types.SetNull(types.ObjectType{AttrTypes: tenantActionAttrTypes}),
	}

	var diags diag.Diagnostics
	got := r.buildInternalInput(context.Background(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}
	if got == nil {
		t.Fatal("expected non-nil input")
	}
	if got.TenantSeverity != "" {
		t.Errorf("expected empty TenantSeverity, got %q", got.TenantSeverity)
	}
	if got.TenantActions != nil {
		t.Errorf("expected nil TenantActions, got %v", got.TenantActions)
	}
}

func TestBuildInternalInput_SeverityOnly(t *testing.T) {
	t.Parallel()

	r := &AnalyticManagedResource{}
	data := AnalyticManagedResourceModel{
		TenantSeverity: types.StringValue("High"),
		TenantActions:  types.SetNull(types.ObjectType{AttrTypes: tenantActionAttrTypes}),
	}

	var diags diag.Diagnostics
	got := r.buildInternalInput(context.Background(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}
	if got.TenantSeverity != "High" {
		t.Errorf("expected TenantSeverity=High, got %q", got.TenantSeverity)
	}
	if got.TenantActions != nil {
		t.Errorf("expected nil TenantActions, got %v", got.TenantActions)
	}
}

func TestBuildInternalInput_ActionsWithParameters(t *testing.T) {
	t.Parallel()

	paramVal, paramDiags := types.MapValue(types.StringType, map[string]attr.Value{
		"id": types.StringValue("smartgroup"),
	})
	if paramDiags.HasError() {
		t.Fatalf("setup: %s", paramDiags.Errors()[0].Detail())
	}

	actionObj, _ := types.ObjectValue(tenantActionAttrTypes, map[string]attr.Value{
		"name":       types.StringValue("SmartGroup"),
		"parameters": paramVal,
	})
	actionsSet, setDiags := types.SetValue(types.ObjectType{AttrTypes: tenantActionAttrTypes}, []attr.Value{actionObj})
	if setDiags.HasError() {
		t.Fatalf("setup: %s", setDiags.Errors()[0].Detail())
	}

	r := &AnalyticManagedResource{}
	data := AnalyticManagedResourceModel{
		TenantSeverity: types.StringNull(),
		TenantActions:  actionsSet,
	}

	var diags diag.Diagnostics
	got := r.buildInternalInput(context.Background(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}
	if len(got.TenantActions) != 1 {
		t.Fatalf("expected 1 tenant action, got %d", len(got.TenantActions))
	}
	if got.TenantActions[0].Name != "SmartGroup" {
		t.Errorf("expected action name=SmartGroup, got %q", got.TenantActions[0].Name)
	}
	if got.TenantActions[0].Parameters != `{"id":"smartgroup"}` {
		t.Errorf("expected parameters=%q, got %q", `{"id":"smartgroup"}`, got.TenantActions[0].Parameters)
	}
}

func TestBuildInternalInput_EmptyActionsSetSendsEmptySlice(t *testing.T) {
	t.Parallel()

	emptySet, setDiags := types.SetValue(types.ObjectType{AttrTypes: tenantActionAttrTypes}, []attr.Value{})
	if setDiags.HasError() {
		t.Fatalf("setup: %s", setDiags.Errors()[0].Detail())
	}

	r := &AnalyticManagedResource{}
	data := AnalyticManagedResourceModel{
		TenantSeverity: types.StringNull(),
		TenantActions:  emptySet,
	}

	var diags diag.Diagnostics
	got := r.buildInternalInput(context.Background(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}
	if got.TenantActions == nil {
		t.Fatal("expected non-nil empty slice (caller distinguishes nil vs empty)")
	}
	if len(got.TenantActions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(got.TenantActions))
	}
}

// TestApplyState_SmokeJamfManaged is a minimal smoke test against an inline Analytic value.
// Fixture-driven tests using real prod GraphQL responses live alongside this file and exercise
// edge cases the smoke test doesn't cover.
func TestApplyState_SmokeJamfManaged(t *testing.T) {
	t.Parallel()

	api := jamfprotect.Analytic{
		UUID:           "00000000-0000-0000-0000-000000000001",
		Name:           "TestJamfAnalytic",
		InputType:      "GPProcessEvent",
		Filter:         `$event.command =~ "evil"`,
		Description:    "Detect evil command",
		Level:          1,
		Severity:       "Medium",
		TenantSeverity: "High",
		Tags:           []string{"mitre"},
		Categories:     []string{"Execution"},
		SnapshotFiles:  []string{},
		Context:        []jamfprotect.AnalyticContext{},
		AnalyticActions: []jamfprotect.AnalyticAction{
			{Name: "Log", Parameters: "{}"},
		},
		TenantActions: []jamfprotect.AnalyticAction{
			{Name: "SmartGroup", Parameters: `{"id":"sg-123"}`},
		},
		Jamf:        true,
		Created:     "2026-01-01T00:00:00Z",
		Updated:     "2026-04-28T00:00:00Z",
		Remediation: "Remove the offending process.",
	}

	r := &AnalyticManagedResource{}
	var data AnalyticManagedResourceModel
	var diags diag.Diagnostics

	r.applyState(context.Background(), &data, api, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}

	if data.ID.ValueString() != api.UUID {
		t.Errorf("ID: expected %q, got %q", api.UUID, data.ID.ValueString())
	}
	if data.SensorType.ValueString() != "Process Event" {
		t.Errorf("SensorType: expected %q, got %q", "Process Event", data.SensorType.ValueString())
	}
	if data.TenantSeverity.ValueString() != "High" {
		t.Errorf("TenantSeverity: expected High, got %q", data.TenantSeverity.ValueString())
	}
	if !data.Jamf.ValueBool() {
		t.Error("Jamf: expected true")
	}
	if data.TenantActions.IsNull() || len(data.TenantActions.Elements()) != 1 {
		t.Errorf("TenantActions: expected 1 element, got null=%v len=%d",
			data.TenantActions.IsNull(), len(data.TenantActions.Elements()))
	}
}
