// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package api_client

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestBuildApiClientInput_RoleIDsAlwaysSent verifies role ids are always a non-nil list. The API
// grants Full Admin to a client created with roleIds omitted and rejects null, so an unset
// role_ids must be sent as an empty list.
func TestBuildApiClientInput_RoleIDsAlwaysSent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		roles   types.Set
		wantLen int
	}{
		{name: "null sends empty list", roles: types.SetNull(types.StringType)},
		{name: "unknown sends empty list", roles: types.SetUnknown(types.StringType)},
		{name: "empty sends empty list", roles: types.SetValueMust(types.StringType, []attr.Value{})},
		{name: "populated sends ids", roles: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("1")}), wantLen: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := buildApiClientInput(context.Background(), ApiClientResourceModel{Name: types.StringValue("c"), RoleIDs: tt.roles}, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if got.RoleIDs == nil {
				t.Fatal("RoleIDs is nil; the SDK would not guard against an implicit Full Admin grant")
			}
			if len(got.RoleIDs) != tt.wantLen {
				t.Fatalf("RoleIDs len = %d, want %d", len(got.RoleIDs), tt.wantLen)
			}
		})
	}
}
