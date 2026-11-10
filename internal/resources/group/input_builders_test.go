// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestBuildGroupInput_RoleIDs verifies null or unknown role ids are omitted and known sets are sent.
func TestBuildGroupInput_RoleIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		roles   types.Set
		wantNil bool
		wantLen int
	}{
		{name: "null omits role ids", roles: types.SetNull(types.StringType), wantNil: true},
		{name: "unknown omits role ids", roles: types.SetUnknown(types.StringType), wantNil: true},
		{name: "empty set clears role ids", roles: types.SetValueMust(types.StringType, []attr.Value{}), wantLen: 0},
		{name: "populated set sends role ids", roles: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("1")}), wantLen: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := buildGroupInput(context.Background(), GroupResourceModel{Name: types.StringValue("g"), RoleIDs: tt.roles}, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if (got.RoleIDs == nil) != tt.wantNil {
				t.Fatalf("RoleIDs nil = %v, want %v", got.RoleIDs == nil, tt.wantNil)
			}
			if len(got.RoleIDs) != tt.wantLen {
				t.Fatalf("RoleIDs len = %d, want %d", len(got.RoleIDs), tt.wantLen)
			}
		})
	}
}
