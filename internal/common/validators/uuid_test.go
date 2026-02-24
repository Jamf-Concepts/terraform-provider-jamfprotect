// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestUUIDValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   types.String
		wantErr bool
	}{
		{
			name:    "valid lowercase uuid",
			value:   types.StringValue("12345678-1234-1234-1234-123456789abc"),
			wantErr: false,
		},
		{
			name:    "valid uppercase uuid",
			value:   types.StringValue("ABCDEF01-2345-6789-ABCD-EF0123456789"),
			wantErr: false,
		},
		{
			name:    "valid mixed case uuid",
			value:   types.StringValue("abCDef01-2345-6789-AbCd-EF0123456789"),
			wantErr: false,
		},
		{
			name:    "invalid format - no dashes",
			value:   types.StringValue("12345678123412341234123456789abc"),
			wantErr: true,
		},
		{
			name:    "invalid format - too short",
			value:   types.StringValue("1234-5678"),
			wantErr: true,
		},
		{
			name:    "invalid format - not hex",
			value:   types.StringValue("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
			wantErr: true,
		},
		{
			name:    "empty string",
			value:   types.StringValue(""),
			wantErr: true,
		},
		{
			name:    "arbitrary string",
			value:   types.StringValue("not-a-uuid"),
			wantErr: true,
		},
		{
			name:    "null value - skipped",
			value:   types.StringNull(),
			wantErr: false,
		},
		{
			name:    "unknown value - skipped",
			value:   types.StringUnknown(),
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := validator.StringRequest{
				ConfigValue: tc.value,
			}
			resp := &validator.StringResponse{}

			UUID().ValidateString(context.Background(), req, resp)

			if tc.wantErr && !resp.Diagnostics.HasError() {
				t.Error("expected error, got none")
			}
			if !tc.wantErr && resp.Diagnostics.HasError() {
				t.Errorf("expected no error, got: %v", resp.Diagnostics.Errors())
			}
		})
	}
}
