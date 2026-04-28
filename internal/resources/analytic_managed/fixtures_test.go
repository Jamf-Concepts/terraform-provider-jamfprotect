// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// loadFixture reads a JSON file from testdata/ and unmarshals it.
func loadFixture[T any](t *testing.T, name string) T {
	t.Helper()
	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %s", path, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal fixture %s: %s", path, err)
	}
	return out
}

// getAnalyticEnvelope mirrors the GraphQL response shape for getAnalytic.
type getAnalyticEnvelope struct {
	Data struct {
		GetAnalytic jamfprotect.Analytic `json:"getAnalytic"`
	} `json:"data"`
}

// updateInternalAnalyticEnvelope mirrors the GraphQL response shape for updateInternalAnalytic.
type updateInternalAnalyticEnvelope struct {
	Data struct {
		UpdateInternalAnalytic jamfprotect.Analytic `json:"updateInternalAnalytic"`
	} `json:"data"`
}

// updateRequestVariables mirrors the GraphQL request variables shape for updateInternalAnalytic.
type updateRequestVariables struct {
	UUID           string                            `json:"uuid"`
	TenantActions  []jamfprotect.AnalyticActionInput `json:"tenantActions"`
	TenantSeverity string                            `json:"tenantSeverity"`
}

// TestApplyState_FromProdGetAnalytic_AppleJeus verifies state mapping against a real
// production getAnalytic response for a Jamf-managed analytic with no tenant overrides.
func TestApplyState_FromProdGetAnalytic_AppleJeus(t *testing.T) {
	t.Parallel()

	env := loadFixture[getAnalyticEnvelope](t, "get_analytic_applejeus_response.json")
	api := env.Data.GetAnalytic

	r := &AnalyticManagedResource{}
	var data AnalyticManagedResourceModel
	var diags diag.Diagnostics

	r.applyState(context.Background(), &data, api, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}

	checks := []struct {
		name     string
		got      string
		expected string
	}{
		{"id", data.ID.ValueString(), "e59e0cdc-eea2-11e9-ba08-a683e73a7372"},
		{"name", data.Name.ValueString(), "AppleJeusMalware"},
		{"label", data.Label.ValueString(), "Applejeus Malware"},
		{"sensor_type", data.SensorType.ValueString(), "File System Event"},
		{"description", data.Description.ValueString(), "Known malware IOC for AppleJeus"},
		{"long_description", data.LongDescription.ValueString(), "A plist name associated with AppleJeus malware was written."},
		{"severity", data.Severity.ValueString(), "High"},
		{"created", data.Created.ValueString(), "2024-02-29T17:13:40.774044Z"},
		{"updated", data.Updated.ValueString(), "2026-04-27T19:03:00.187832Z"},
	}

	for _, c := range checks {
		if c.got != c.expected {
			t.Errorf("%s: expected %q, got %q", c.name, c.expected, c.got)
		}
	}

	if data.Level.ValueInt64() != 1 {
		t.Errorf("level: expected 1, got %d", data.Level.ValueInt64())
	}

	if !data.Jamf.ValueBool() {
		t.Error("jamf: expected true")
	}

	// tenant_severity is null in the fixture (server returned null).
	if !data.TenantSeverity.IsNull() {
		t.Errorf("tenant_severity: expected null, got %q", data.TenantSeverity.ValueString())
	}

	// tenant_actions is null in the source JSON; applyState produces an empty (non-null)
	// set so plan diffs are predictable.
	if data.TenantActions.IsNull() {
		t.Error("tenant_actions: expected empty (non-null) set")
	}
	if len(data.TenantActions.Elements()) != 0 {
		t.Errorf("tenant_actions: expected 0 elements, got %d", len(data.TenantActions.Elements()))
	}

	// Filter is preserved — the fixture filter contains no double-backslashes so it round-trips unchanged.
	expectedFilter := `("LaunchDaemon" IN $tags OR "LaunchAgent" IN $tags) AND $context.Name.value IN {"org.jmttrading.plist", "com.celastradepro.plist"}`
	if data.Filter.ValueString() != expectedFilter {
		t.Errorf("filter:\n  expected %q\n  got      %q", expectedFilter, data.Filter.ValueString())
	}

	// Categories: ["Known Malicious File"]
	cats := data.Categories.Elements()
	if len(cats) != 1 {
		t.Fatalf("categories: expected 1 element, got %d", len(cats))
	}

	// Empty fields stay empty sets.
	if len(data.Tags.Elements()) != 0 {
		t.Errorf("tags: expected empty, got %d elements", len(data.Tags.Elements()))
	}
	if len(data.SnapshotFiles.Elements()) != 0 {
		t.Errorf("snapshot_files: expected empty, got %d elements", len(data.SnapshotFiles.Elements()))
	}
	if len(data.ContextItem.Elements()) != 0 {
		t.Errorf("context_item: expected empty, got %d elements", len(data.ContextItem.Elements()))
	}
}

// TestApplyState_FromProdUpdateResponse verifies state mapping against a real production
// updateInternalAnalytic response. The response shape is a partial Analytic (only the fields
// the mutation explicitly returns) — the rest unmarshal to zero values, but the mutation in
// our SDK uses the full AnalyticFields fragment, so in practice we get a full payload back.
// This test exercises the partial-response shape just to confirm graceful handling.
func TestApplyState_FromProdUpdateResponse_Partial(t *testing.T) {
	t.Parallel()

	env := loadFixture[updateInternalAnalyticEnvelope](t, "update_internal_analytic_response.json")
	api := env.Data.UpdateInternalAnalytic

	r := &AnalyticManagedResource{}
	var data AnalyticManagedResourceModel
	var diags diag.Diagnostics

	r.applyState(context.Background(), &data, api, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors()[0].Detail())
	}

	if data.TenantSeverity.ValueString() != "Low" {
		t.Errorf("tenant_severity: expected Low, got %q", data.TenantSeverity.ValueString())
	}

	actions := data.TenantActions.Elements()
	if len(actions) != 2 {
		t.Fatalf("tenant_actions: expected 2 elements, got %d", len(actions))
	}

	// One of the actions must be SmartGroup with parameters.id=yes.
	foundSmartGroup := false
	for _, a := range actions {
		obj := a.(types.Object)
		name := obj.Attributes()["name"].(types.String).ValueString()
		if name != "SmartGroup" {
			continue
		}
		params := obj.Attributes()["parameters"].(types.Map)
		if params.IsNull() {
			t.Fatal("SmartGroup action has null parameters")
		}
		idVal := params.Elements()["id"].(types.String).ValueString()
		if idVal != "yes" {
			t.Errorf("SmartGroup parameters.id: expected yes, got %q", idVal)
		}
		foundSmartGroup = true
	}
	if !foundSmartGroup {
		t.Error("expected to find SmartGroup tenant action")
	}
}

// TestBuildInternalInput_MatchesProdRequestShape builds an InternalAnalyticInput from a model
// matching the production update request, marshals the resulting fields, and confirms they
// match the on-the-wire variables shape.
func TestBuildInternalInput_MatchesProdRequestShape(t *testing.T) {
	t.Parallel()

	wantVars := loadFixture[updateRequestVariables](t, "update_internal_analytic_request_variables.json")

	// Build a model with the same intent: tenant_severity=Low and two tenant actions.
	reportObj, _ := types.ObjectValue(tenantActionAttrTypes, map[string]attr.Value{
		"name":       types.StringValue("Report"),
		"parameters": types.MapNull(types.StringType),
	})

	smartGroupParams, paramDiags := types.MapValue(types.StringType, map[string]attr.Value{
		"id": types.StringValue("yes"),
	})
	if paramDiags.HasError() {
		t.Fatalf("setup: %s", paramDiags.Errors()[0].Detail())
	}
	smartGroupObj, _ := types.ObjectValue(tenantActionAttrTypes, map[string]attr.Value{
		"name":       types.StringValue("SmartGroup"),
		"parameters": smartGroupParams,
	})

	actionsSet, setDiags := types.SetValue(
		types.ObjectType{AttrTypes: tenantActionAttrTypes},
		[]attr.Value{reportObj, smartGroupObj},
	)
	if setDiags.HasError() {
		t.Fatalf("setup: %s", setDiags.Errors()[0].Detail())
	}

	r := &AnalyticManagedResource{}
	data := AnalyticManagedResourceModel{
		ID:             types.StringValue(wantVars.UUID),
		TenantSeverity: types.StringValue("Low"),
		TenantActions:  actionsSet,
	}

	var diags diag.Diagnostics
	got := r.buildInternalInput(context.Background(), data, &diags)
	if diags.HasError() {
		t.Fatalf("buildInternalInput: %s", diags.Errors()[0].Detail())
	}

	if got.TenantSeverity != "Low" {
		t.Errorf("tenant_severity: expected Low, got %q", got.TenantSeverity)
	}

	if len(got.TenantActions) != len(wantVars.TenantActions) {
		t.Fatalf("tenant_actions: expected %d, got %d", len(wantVars.TenantActions), len(got.TenantActions))
	}

	// Set ordering is non-deterministic, so look up by name.
	gotByName := map[string]string{}
	for _, a := range got.TenantActions {
		gotByName[a.Name] = a.Parameters
	}
	for _, want := range wantVars.TenantActions {
		gotParams, ok := gotByName[want.Name]
		if !ok {
			t.Errorf("missing action %q in built input", want.Name)
			continue
		}
		if !jsonEqual(t, gotParams, want.Parameters) {
			t.Errorf("action %q parameters:\n  expected %s\n  got      %s",
				want.Name, want.Parameters, gotParams)
		}
	}
}

// jsonEqual compares two JSON strings semantically (ignoring key order and whitespace).
// "{}" and an empty parameter object both decode to an empty map.
func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()

	if a == b {
		return true
	}

	normalize := func(s string) (any, bool) {
		if s == "" {
			return map[string]any{}, true
		}
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return nil, false
		}
		return v, true
	}

	av, aok := normalize(a)
	bv, bok := normalize(b)
	if !aok || !bok {
		return false
	}
	ab, _ := json.Marshal(av)
	bb, _ := json.Marshal(bv)
	return string(ab) == string(bb)
}
