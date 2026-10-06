// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed

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

// fakeProtectAPI serves the token endpoint, getAnalytic and updateInternalAnalytic, returning
// the partial mutation response the real API sends and recording the mutation variables.
type fakeProtectAPI struct {
	mu          sync.Mutex
	getAnalytic jamfprotect.Analytic
	updateVars  map[string]any
}

// ServeHTTP implements http.Handler for fakeProtectAPI.
func (f *fakeProtectAPI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if req.URL.Path == "/token" {
		_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
		return
	}

	var body struct {
		Variables map[string]any `json:"variables"`
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
		f.updateVars = body.Variables
		if v, ok := body.Variables["tenantSeverity"].(string); ok {
			f.getAnalytic.TenantSeverity = v
		}
		partial := map[string]any{
			"uuid":           f.getAnalytic.UUID,
			"tenantSeverity": f.getAnalytic.TenantSeverity,
			"tenantActions":  f.getAnalytic.TenantActions,
		}
		payload = map[string]any{"data": map[string]any{"updateInternalAnalytic": partial}}
	default:
		payload = map[string]any{"data": map[string]any{"getAnalytic": f.getAnalytic}}
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// managedStateFromAPI builds a resource model for a Jamf-managed analytic as Read would.
func managedStateFromAPI(t *testing.T, api jamfprotect.Analytic) AnalyticManagedResourceModel {
	t.Helper()
	var data AnalyticManagedResourceModel
	var diags diag.Diagnostics
	(&AnalyticManagedResource{}).applyState(context.Background(), &data, api, &diags)
	if diags.HasError() {
		t.Fatalf("applyState: %s", diags.Errors()[0].Detail())
	}
	data.Timeouts = common.EmptyTimeoutsValue()
	return data
}

// TestUpdate_RefreshesStateFromGetAnalytic verifies that Update builds state from a follow-up
// GetAnalytic rather than the partial mutation response, and that a severity-only change on an
// analytic with no tenant override leaves tenantActions out of the mutation.
func TestUpdate_RefreshesStateFromGetAnalytic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	env := loadFixture[getAnalyticEnvelope](t, "get_analytic_applejeus_response.json")
	api := &fakeProtectAPI{getAnalytic: env.Data.GetAnalytic}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	r := &AnalyticManagedResource{client: jamfprotect.NewClient(srv.URL, "client-id", "client-secret")}

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	var identityResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &identityResp)
	objType := schemaResp.Schema.Type().TerraformType(ctx)

	prior := managedStateFromAPI(t, env.Data.GetAnalytic)
	planned := prior
	planned.TenantSeverity = types.StringValue("Low")
	planned.TenantActions = types.SetUnknown(prior.TenantActions.ElementType(ctx))

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

	var got AnalyticManagedResourceModel
	if d := resp.State.Get(ctx, &got); d.HasError() {
		t.Fatalf("get state: %s", d.Errors()[0].Detail())
	}
	if got.LongDescription.ValueString() != env.Data.GetAnalytic.LongDescription {
		t.Errorf("long_description: expected %q, got %q", env.Data.GetAnalytic.LongDescription, got.LongDescription.ValueString())
	}
	if got.Remediation.ValueString() != env.Data.GetAnalytic.Remediation {
		t.Errorf("remediation: expected %q, got %q", env.Data.GetAnalytic.Remediation, got.Remediation.ValueString())
	}
	if got.TenantSeverity.ValueString() != "Low" {
		t.Errorf("tenant_severity: expected Low, got %q", got.TenantSeverity.ValueString())
	}
	if !got.TenantActions.IsNull() {
		t.Errorf("tenant_actions: expected null, got %v", got.TenantActions)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if _, sent := api.updateVars["tenantActions"]; sent {
		t.Errorf("expected tenantActions to be omitted from the mutation, got %v", api.updateVars["tenantActions"])
	}
	if api.updateVars["tenantSeverity"] != "Low" {
		t.Errorf("expected tenantSeverity=Low in the mutation, got %v", api.updateVars["tenantSeverity"])
	}
}
