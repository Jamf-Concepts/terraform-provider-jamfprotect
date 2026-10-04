// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"
	"testing"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestBuildHeadersList_WriteOnly verifies that headers managed through value_wo keep their values out of state.
func TestBuildHeadersList_WriteOnly(t *testing.T) {
	t.Parallel()

	apiHeaders := []jamfprotect.ReportClientHeader{
		{Header: "Authorization", Value: "Bearer secret"},
		{Header: "Content-Type", Value: "application/json"},
	}

	tests := []struct {
		name        string
		woHeaders   map[headerPosition]endpointHeaderModel
		endpoint    int
		wantValues  []types.String
		wantVersion []types.String
	}{
		{
			name:        "no write-only headers",
			wantValues:  []types.String{types.StringValue("Bearer secret"), types.StringValue("application/json")},
			wantVersion: []types.String{types.StringNull(), types.StringNull()},
		},
		{
			name: "write-only header at matching position",
			woHeaders: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 0}: {Header: types.StringValue("Authorization"), ValueWOVersion: types.StringValue("1")},
			},
			wantValues:  []types.String{types.StringNull(), types.StringValue("application/json")},
			wantVersion: []types.String{types.StringValue("1"), types.StringNull()},
		},
		{
			name: "write-only header with a different name is not matched",
			woHeaders: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 0}: {Header: types.StringValue("X-Api-Key"), ValueWOVersion: types.StringValue("1")},
			},
			wantValues:  []types.String{types.StringValue("Bearer secret"), types.StringValue("application/json")},
			wantVersion: []types.String{types.StringNull(), types.StringNull()},
		},
		{
			name: "write-only header moved to another position is matched by name",
			woHeaders: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 1}: {Header: types.StringValue("authorization"), ValueWOVersion: types.StringValue("1")},
			},
			wantValues:  []types.String{types.StringNull(), types.StringValue("application/json")},
			wantVersion: []types.String{types.StringValue("1"), types.StringNull()},
		},
		{
			name: "write-only header on another endpoint is not matched",
			woHeaders: map[headerPosition]endpointHeaderModel{
				{endpoint: 1, header: 0}: {Header: types.StringValue("Authorization"), ValueWOVersion: types.StringValue("1")},
			},
			wantValues:  []types.String{types.StringValue("Bearer secret"), types.StringValue("application/json")},
			wantVersion: []types.String{types.StringNull(), types.StringNull()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			list := buildHeadersList(apiHeaders, tt.endpoint, tt.woHeaders, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			var got []endpointHeaderModel
			diags.Append(list.ElementsAs(context.Background(), &got, false)...)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if len(got) != len(apiHeaders) {
				t.Fatalf("got %d headers, want %d", len(got), len(apiHeaders))
			}
			for i, h := range got {
				if !h.Value.Equal(tt.wantValues[i]) {
					t.Errorf("header %d value = %v, want %v", i, h.Value, tt.wantValues[i])
				}
				if !h.ValueWOVersion.Equal(tt.wantVersion[i]) {
					t.Errorf("header %d value_wo_version = %v, want %v", i, h.ValueWOVersion, tt.wantVersion[i])
				}
				if !h.ValueWO.IsNull() {
					t.Errorf("header %d value_wo = %v, want null", i, h.ValueWO)
				}
			}
		})
	}
}

// TestBuildHTTPEndpointsState_WriteOnlyHeaderMoved verifies that a value_wo header whose position
// moved on the server, after another header was removed out of band, stays out of state.
func TestBuildHTTPEndpointsState_WriteOnlyHeaderMoved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	woHeaders := map[headerPosition]endpointHeaderModel{
		{endpoint: 0, header: 1}: {Header: types.StringValue("Authorization"), ValueWOVersion: types.StringValue("1")},
	}
	clients := []jamfprotect.ReportClient{{
		Type: "Http",
		Params: jamfprotect.ReportClientParams{
			URL:     "https://example.invalid/hook",
			Method:  "POST",
			Headers: []jamfprotect.ReportClientHeader{{Header: "Authorization", Value: "Bearer SECRET"}},
		},
	}}

	var diags diag.Diagnostics
	list := buildHTTPEndpointsState(clients, woHeaders, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	var endpoints []httpEndpointBlockModel
	diags.Append(list.ElementsAs(ctx, &endpoints, false)...)
	if diags.HasError() || len(endpoints) != 1 {
		t.Fatalf("expected one endpoint, got %d: %v", len(endpoints), diags)
	}
	var headers []endpointHeaderModel
	diags.Append(endpoints[0].Headers.ElementsAs(ctx, &headers, false)...)
	if diags.HasError() || len(headers) != 1 {
		t.Fatalf("expected one header, got %d: %v", len(headers), diags)
	}
	if !headers[0].Value.IsNull() {
		t.Errorf("value = %v, want null", headers[0].Value)
	}
	if !headers[0].ValueWOVersion.Equal(types.StringValue("1")) {
		t.Errorf("value_wo_version = %v, want \"1\"", headers[0].ValueWOVersion)
	}
}

// TestMatchWriteOnlyHeaders_PositionWins verifies that exact position matches are assigned before
// name fallbacks, so a fallback cannot take a prior header another API header matches exactly.
func TestMatchWriteOnlyHeaders_PositionWins(t *testing.T) {
	t.Parallel()

	woHeaders := map[headerPosition]endpointHeaderModel{
		{endpoint: 0, header: 1}: {Header: types.StringValue("Authorization"), ValueWOVersion: types.StringValue("b")},
		{endpoint: 0, header: 2}: {Header: types.StringValue("Authorization"), ValueWOVersion: types.StringValue("c")},
	}
	headers := []jamfprotect.ReportClientHeader{
		{Header: "Authorization"},
		{Header: "Authorization"},
		{Header: "Authorization"},
	}

	matched := matchWriteOnlyHeaders(headers, 0, woHeaders)
	if len(matched) != 2 {
		t.Fatalf("expected 2 matches, got %d: %v", len(matched), matched)
	}
	if got := matched[1].ValueWOVersion.ValueString(); got != "b" {
		t.Errorf("header 1 version = %q, want b", got)
	}
	if got := matched[2].ValueWOVersion.ValueString(); got != "c" {
		t.Errorf("header 2 version = %q, want c", got)
	}
	if _, ok := matched[0]; ok {
		t.Errorf("header 0 should not match, got %v", matched[0])
	}
}
