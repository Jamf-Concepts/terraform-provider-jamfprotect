// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// fakeProtectAPI serves the token endpoint, getAnalytic and updateAnalytic, counting getAnalytic
// calls and recording the analytic actions each update sends.
type fakeProtectAPI struct {
	mu          sync.Mutex
	analytic    jamfprotect.Analytic
	getCalls    int
	sentActions []jamfprotect.AnalyticAction
}

// ServeHTTP implements http.Handler for fakeProtectAPI.
func (f *fakeProtectAPI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if req.URL.Path == "/token" {
		_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
		return
	}

	var body struct {
		Variables struct {
			Description     string                       `json:"description"`
			AnalyticActions []jamfprotect.AnalyticAction `json:"analyticActions"`
		} `json:"variables"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	var payload any
	switch req.URL.Path {
	case "/app":
		f.sentActions = body.Variables.AnalyticActions
		f.analytic.Description = body.Variables.Description
		f.analytic.AnalyticActions = body.Variables.AnalyticActions
		payload = map[string]any{"data": map[string]any{"updateAnalytic": f.analytic}}
	default:
		f.getCalls++
		payload = map[string]any{"data": map[string]any{"getAnalytic": f.analytic}}
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// consoleAnalytic returns an analytic carrying the console actions, as the API returns it.
func consoleAnalytic() jamfprotect.Analytic {
	return jamfprotect.Analytic{
		UUID:            "00000000-0000-0000-0000-000000000001",
		Name:            "tf-unit-analytic",
		InputType:       "GPFSEvent",
		Filter:          "$event.type == 0",
		Description:     "before",
		Severity:        "Low",
		Tags:            []string{},
		Categories:      []string{},
		SnapshotFiles:   []string{},
		Context:         []jamfprotect.AnalyticContext{},
		AnalyticActions: []jamfprotect.AnalyticAction{{Name: "Report", Parameters: "{}"}, {Name: "SmartGroup", Parameters: `{"id":"old-group"}`}, {Name: "Webhook", Parameters: `{"url":"https://example.invalid/hook"}`}},
	}
}

// analyticStateFromAPI builds a resource model for an analytic as Read would.
func analyticStateFromAPI(t *testing.T, api jamfprotect.Analytic) AnalyticResourceModel {
	t.Helper()
	var data AnalyticResourceModel
	var diags diag.Diagnostics
	(&AnalyticResource{}).applyState(context.Background(), &data, api, &diags)
	if diags.HasError() {
		t.Fatalf("applyState: %s", diags.Errors()[0].Detail())
	}
	data.Timeouts = common.EmptyTimeoutsValue()
	return data
}

// TestUpdate_KeepsConsoleActions verifies that a description-only update sends every console
// action, reading them from the API when prior state predates analytic_actions.
func TestUpdate_KeepsConsoleActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		nullInState  bool
		wantGetCalls int
	}{
		{name: "actions in state", nullInState: false, wantGetCalls: 0},
		{name: "state predates analytic_actions", nullInState: true, wantGetCalls: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			api := &fakeProtectAPI{analytic: consoleAnalytic()}
			srv := httptest.NewServer(api)
			t.Cleanup(srv.Close)

			r := &AnalyticResource{client: jamfprotect.NewClient(srv.URL, "client-id", "client-secret")}

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			var identityResp resource.IdentitySchemaResponse
			r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &identityResp)
			objType := schemaResp.Schema.Type().TerraformType(ctx)

			prior := analyticStateFromAPI(t, consoleAnalytic())
			if tt.nullInState {
				prior.AnalyticActions = types.ListNull(types.ObjectType{AttrTypes: analyticActionAttrTypes})
			}
			planned := prior
			planned.Description = types.StringValue("after")
			planned.AnalyticActions = types.ListUnknown(types.ObjectType{AttrTypes: analyticActionAttrTypes})

			req := resource.UpdateRequest{
				State: tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(objType, nil)},
				Plan:  tfsdk.Plan{Schema: schemaResp.Schema, Raw: tftypes.NewValue(objType, nil)},
			}
			if d := req.State.Set(ctx, &prior); d.HasError() {
				t.Fatalf("set state: %s", d.Errors()[0].Detail())
			}
			if d := req.Plan.Set(ctx, &planned); d.HasError() {
				t.Fatalf("set plan: %s", d.Errors()[0].Detail())
			}
			resp := resource.UpdateResponse{
				State: tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(objType, nil)},
				Identity: &tfsdk.ResourceIdentity{
					Schema: identityResp.IdentitySchema,
					Raw:    tftypes.NewValue(identityResp.IdentitySchema.Type().TerraformType(ctx), nil),
				},
			}

			r.Update(ctx, req, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Update: %s: %s", resp.Diagnostics.Errors()[0].Summary(), resp.Diagnostics.Errors()[0].Detail())
			}

			api.mu.Lock()
			defer api.mu.Unlock()
			if api.getCalls != tt.wantGetCalls {
				t.Errorf("expected %d getAnalytic calls, got %d", tt.wantGetCalls, api.getCalls)
			}
			want := consoleAnalytic().AnalyticActions
			if len(api.sentActions) != len(want) {
				t.Fatalf("expected %d actions sent, got %d: %v", len(want), len(api.sentActions), api.sentActions)
			}
			for i := range want {
				if api.sentActions[i] != want[i] {
					t.Errorf("action %d: expected %+v, got %+v", i, want[i], api.sentActions[i])
				}
			}

			var got AnalyticResourceModel
			if d := resp.State.Get(ctx, &got); d.HasError() {
				t.Fatalf("get state: %s", d.Errors()[0].Detail())
			}
			if len(got.AnalyticActions.Elements()) != len(want) {
				t.Errorf("expected %d analytic_actions in state, got %v", len(want), got.AnalyticActions)
			}
		})
	}
}
