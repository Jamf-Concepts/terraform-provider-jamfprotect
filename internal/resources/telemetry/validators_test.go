// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestAdditionalEventsValidator verifies category events are rejected and other values pass.
func TestAdditionalEventsValidator(t *testing.T) {
	tests := []struct {
		name       string
		value      types.Set
		wantErrors int
	}{
		{name: "null", value: types.SetNull(types.StringType), wantErrors: 0},
		{name: "unknown", value: types.SetUnknown(types.StringType), wantErrors: 0},
		{name: "empty", value: types.SetValueMust(types.StringType, []attr.Value{}), wantErrors: 0},
		{
			name:       "unmodelled events",
			value:      types.SetValueMust(types.StringType, []attr.Value{types.StringValue("xpc_connect"), types.StringValue("fork")}),
			wantErrors: 0,
		},
		{
			name:       "unknown element",
			value:      types.SetValueMust(types.StringType, []attr.Value{types.StringUnknown(), types.StringValue("fork")}),
			wantErrors: 0,
		},
		{
			name:       "category events",
			value:      types.SetValueMust(types.StringType, []attr.Value{types.StringValue("sudo"), types.StringValue("xpc_connect"), types.StringValue("network_connect")}),
			wantErrors: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validator.SetRequest{Path: path.Root("additional_events"), ConfigValue: tt.value}
			resp := &validator.SetResponse{}
			additionalEventsValidator{}.ValidateSet(context.Background(), req, resp)
			if got := resp.Diagnostics.ErrorsCount(); got != tt.wantErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.wantErrors, got, resp.Diagnostics)
			}
		})
	}
}
