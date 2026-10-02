// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

const (
	testATCUUID    = "5b8a2426-cba3-4805-9688-982c54545f3c"
	testTPUUID     = "9d523b8e-c527-4525-8768-92243b55e0b6"
	testCustomUUID = "11111111-1111-4111-8111-111111111111"
)

// testManagedAnalyticSets is a listAnalyticSets response holding the two Jamf-managed sets.
var testManagedAnalyticSets = []jamfprotect.AnalyticSet{
	{UUID: testATCUUID, Name: advancedThreatControlsName, Managed: true},
	{UUID: testTPUUID, Name: tamperPreventionName, Managed: true},
}

// newTestPlanResource returns a PlanResource whose client talks to a fake API that
// answers listAnalyticSets with sets.
func newTestPlanResource(t *testing.T, sets []jamfprotect.AnalyticSet) *PlanResource {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
			return
		}
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !strings.Contains(body.Query, "listAnalyticSets") {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"data": map[string]any{
				"listAnalyticSets": map[string]any{
					"items":    sets,
					"pageInfo": map[string]any{"next": nil, "total": len(sets)},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)
	return &PlanResource{client: jamfprotect.NewClient(server.URL, "id", "secret")}
}

// testPlanModel returns a plan model holding only the attributes buildVariables requires.
func testPlanModel() PlanResourceModel {
	return PlanResourceModel{
		Name:                   types.StringValue("test"),
		ActionConfiguration:    types.StringValue("1"),
		ReportingInterval:      types.Int64Value(1440),
		ExceptionSets:          types.SetNull(types.StringType),
		AnalyticSets:           types.SetNull(types.StringType),
		AdvancedThreatControls: types.StringNull(),
		TamperPrevention:       types.StringNull(),
	}
}

func TestBuildVariables_UnknownSetsAreOmitted(t *testing.T) {
	t.Parallel()

	data := testPlanModel()
	data.ExceptionSets = types.SetUnknown(types.StringType)
	data.AnalyticSets = types.SetUnknown(types.StringType)

	var diags diag.Diagnostics
	input := (&PlanResource{}).buildVariables(context.Background(), data, "fqdn", "", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if input.ExceptionSets != nil {
		t.Errorf("ExceptionSets = %#v, want nil so the API keeps current membership", input.ExceptionSets)
	}
	if input.AnalyticSets != nil {
		t.Errorf("AnalyticSets = %#v, want nil so the API keeps current membership", input.AnalyticSets)
	}
}

func TestBuildVariables_NullSetsAreOmitted(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	input := (&PlanResource{}).buildVariables(context.Background(), testPlanModel(), "fqdn", "", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if input.ExceptionSets != nil {
		t.Errorf("ExceptionSets = %#v, want nil", input.ExceptionSets)
	}
	if input.AnalyticSets != nil {
		t.Errorf("AnalyticSets = %#v, want nil", input.AnalyticSets)
	}
}

func TestBuildVariables_EmptySetsClearMembership(t *testing.T) {
	t.Parallel()

	data := testPlanModel()
	data.ExceptionSets = types.SetValueMust(types.StringType, []attr.Value{})
	data.AnalyticSets = types.SetValueMust(types.StringType, []attr.Value{})

	var diags diag.Diagnostics
	input := (&PlanResource{}).buildVariables(context.Background(), data, "fqdn", "", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if input.ExceptionSets == nil || len(input.ExceptionSets) != 0 {
		t.Errorf("ExceptionSets = %#v, want non-nil empty slice", input.ExceptionSets)
	}
	if input.AnalyticSets == nil || len(input.AnalyticSets) != 0 {
		t.Errorf("AnalyticSets = %#v, want non-nil empty slice", input.AnalyticSets)
	}
}

func TestBuildVariables_KnownExceptionSetsPassThrough(t *testing.T) {
	t.Parallel()

	data := testPlanModel()
	data.ExceptionSets = types.SetValueMust(types.StringType, []attr.Value{types.StringValue(testCustomUUID)})

	var diags diag.Diagnostics
	input := (&PlanResource{}).buildVariables(context.Background(), data, "fqdn", "", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(input.ExceptionSets) != 1 || input.ExceptionSets[0] != testCustomUUID {
		t.Errorf("ExceptionSets = %#v, want [%s]", input.ExceptionSets, testCustomUUID)
	}
}

func TestBuildVariables_AnalyticSetsCarriedWithManagedSets(t *testing.T) {
	t.Parallel()

	data := testPlanModel()
	data.AnalyticSets = types.SetValueMust(types.StringType, []attr.Value{types.StringValue(testCustomUUID)})
	data.AdvancedThreatControls = types.StringValue("Block and report")
	data.TamperPrevention = types.StringValue("Block and report")

	var diags diag.Diagnostics
	input := newTestPlanResource(t, testManagedAnalyticSets).buildVariables(context.Background(), data, "fqdn", "", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	want := []jamfprotect.PlanAnalyticSetInput{
		{Type: "Report", UUID: testCustomUUID},
		{Type: "Prevent", UUID: testATCUUID},
		{Type: "Prevent", UUID: testTPUUID},
	}
	if len(input.AnalyticSets) != len(want) {
		t.Fatalf("AnalyticSets = %#v, want %#v", input.AnalyticSets, want)
	}
	for i := range want {
		if input.AnalyticSets[i] != want[i] {
			t.Errorf("AnalyticSets[%d] = %#v, want %#v", i, input.AnalyticSets[i], want[i])
		}
	}
}

func TestBuildVariables_ManagedSetsIgnoreCustomNamesakes(t *testing.T) {
	t.Parallel()

	sets := append([]jamfprotect.AnalyticSet{
		{UUID: testCustomUUID, Name: advancedThreatControlsName},
		{UUID: "22222222-2222-4222-8222-222222222222", Name: tamperPreventionName},
	}, testManagedAnalyticSets...)
	data := testPlanModel()
	data.AdvancedThreatControls = types.StringValue("Block and report")
	data.TamperPrevention = types.StringValue("Block and report")

	var diags diag.Diagnostics
	input := newTestPlanResource(t, sets).buildVariables(context.Background(), data, "fqdn", "", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	want := []jamfprotect.PlanAnalyticSetInput{
		{Type: "Prevent", UUID: testATCUUID},
		{Type: "Prevent", UUID: testTPUUID},
	}
	if len(input.AnalyticSets) != len(want) {
		t.Fatalf("AnalyticSets = %#v, want %#v", input.AnalyticSets, want)
	}
	for i := range want {
		if input.AnalyticSets[i] != want[i] {
			t.Errorf("AnalyticSets[%d] = %#v, want %#v", i, input.AnalyticSets[i], want[i])
		}
	}
}
