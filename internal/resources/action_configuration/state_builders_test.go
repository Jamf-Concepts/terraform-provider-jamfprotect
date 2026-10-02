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
