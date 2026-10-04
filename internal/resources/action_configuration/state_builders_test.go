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
			list := buildHeadersList(apiHeaders, matchWriteOnlyHeaders(apiHeaders, tt.endpoint, tt.woHeaders), tt.woHeaders, false, &diags)
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

// TestBuildHTTPEndpointsState_WriteOnlyFailsClosed verifies that a value_wo secret stays out of
// state when its header moved, its endpoint shifted or it was renamed out of band, and that plain
// header values stay in state when every value_wo header is matched.
func TestBuildHTTPEndpointsState_WriteOnlyFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	httpClient := func(headers ...jamfprotect.ReportClientHeader) jamfprotect.ReportClient {
		return jamfprotect.ReportClient{Type: "Http", Params: jamfprotect.ReportClientParams{URL: "https://example.invalid/hook", Method: "POST", Headers: headers}}
	}
	auth := jamfprotect.ReportClientHeader{Header: "Authorization", Value: "Bearer SECRET"}
	contentType := jamfprotect.ReportClientHeader{Header: "Content-Type", Value: "application/json"}
	woAuth := endpointHeaderModel{Header: types.StringValue("Authorization"), ValueWOVersion: types.StringValue("1")}

	tests := []struct {
		name        string
		woHeaders   map[headerPosition]endpointHeaderModel
		clients     []jamfprotect.ReportClient
		wantValues  [][]types.String
		wantVersion [][]types.String
		wantWarning bool
	}{
		{
			name:        "all write-only headers matched keeps plain values",
			woHeaders:   map[headerPosition]endpointHeaderModel{{endpoint: 0, header: 1}: woAuth},
			clients:     []jamfprotect.ReportClient{httpClient(contentType, auth)},
			wantValues:  [][]types.String{{types.StringValue("application/json"), types.StringNull()}},
			wantVersion: [][]types.String{{types.StringNull(), types.StringValue("1")}},
		},
		{
			name:        "header moved within its endpoint",
			woHeaders:   map[headerPosition]endpointHeaderModel{{endpoint: 0, header: 1}: woAuth},
			clients:     []jamfprotect.ReportClient{httpClient(auth)},
			wantValues:  [][]types.String{{types.StringNull()}},
			wantVersion: [][]types.String{{types.StringValue("1")}},
		},
		{
			name:        "earlier endpoint deleted",
			woHeaders:   map[headerPosition]endpointHeaderModel{{endpoint: 1, header: 0}: woAuth},
			clients:     []jamfprotect.ReportClient{httpClient(auth, contentType)},
			wantValues:  [][]types.String{{types.StringNull(), types.StringNull()}},
			wantVersion: [][]types.String{{types.StringNull(), types.StringNull()}},
			wantWarning: true,
		},
		{
			name:      "header renamed on the server",
			woHeaders: map[headerPosition]endpointHeaderModel{{endpoint: 0, header: 0}: woAuth},
			clients: []jamfprotect.ReportClient{
				httpClient(jamfprotect.ReportClientHeader{Header: "X-Api-Key", Value: "Bearer SECRET"}),
				httpClient(contentType),
			},
			wantValues:  [][]types.String{{types.StringNull()}, {types.StringNull()}},
			wantVersion: [][]types.String{{types.StringNull()}, {types.StringNull()}},
			wantWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			list := buildHTTPEndpointsState(tt.clients, tt.woHeaders, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if got := diags.WarningsCount() > 0; got != tt.wantWarning {
				t.Errorf("warning emitted = %t, want %t: %v", got, tt.wantWarning, diags)
			}
			var endpoints []httpEndpointBlockModel
			diags.Append(list.ElementsAs(ctx, &endpoints, false)...)
			if diags.HasError() || len(endpoints) != len(tt.wantValues) {
				t.Fatalf("got %d endpoints, want %d: %v", len(endpoints), len(tt.wantValues), diags)
			}
			for i, endpoint := range endpoints {
				var headers []endpointHeaderModel
				diags.Append(endpoint.Headers.ElementsAs(ctx, &headers, false)...)
				if diags.HasError() || len(headers) != len(tt.wantValues[i]) {
					t.Fatalf("endpoint %d: got %d headers, want %d: %v", i, len(headers), len(tt.wantValues[i]), diags)
				}
				for j, h := range headers {
					if !h.Value.Equal(tt.wantValues[i][j]) {
						t.Errorf("endpoint %d header %d value = %v, want %v", i, j, h.Value, tt.wantValues[i][j])
					}
					if !h.ValueWOVersion.Equal(tt.wantVersion[i][j]) {
						t.Errorf("endpoint %d header %d value_wo_version = %v, want %v", i, j, h.ValueWOVersion, tt.wantVersion[i][j])
					}
				}
			}
		})
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
	if got := matched[1]; got != (headerPosition{endpoint: 0, header: 1}) {
		t.Errorf("header 1 matched %v, want prior header 1", got)
	}
	if got := matched[2]; got != (headerPosition{endpoint: 0, header: 2}) {
		t.Errorf("header 2 matched %v, want prior header 2", got)
	}
	if _, ok := matched[0]; ok {
		t.Errorf("header 0 should not match, got %v", matched[0])
	}
}
