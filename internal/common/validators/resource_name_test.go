// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestResourceNameValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   types.String
		wantErr bool
	}{
		{
			name:    "valid short name",
			value:   types.StringValue("a"),
			wantErr: false,
		},
		{
			name:    "valid typical name",
			value:   types.StringValue("My Action Configuration"),
			wantErr: false,
		},
		{
			name:    "valid 255 chars",
			value:   types.StringValue(strings.Repeat("a", 255)),
			wantErr: false,
		},
		{
			name:    "valid with internal whitespace",
			value:   types.StringValue("name with  spaces"),
			wantErr: false,
		},
		{
			name:    "invalid empty string",
			value:   types.StringValue(""),
			wantErr: true,
		},
		{
			name:    "invalid 256 chars",
			value:   types.StringValue(strings.Repeat("a", 256)),
			wantErr: true,
		},
		{
			name:    "invalid leading space",
			value:   types.StringValue(" leading"),
			wantErr: true,
		},
		{
			name:    "invalid trailing space",
			value:   types.StringValue("trailing "),
			wantErr: true,
		},
		{
			name:    "invalid leading and trailing space",
			value:   types.StringValue(" both "),
			wantErr: true,
		},
		{
			name:    "invalid leading tab",
			value:   types.StringValue("\tname"),
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

			ResourceName().ValidateString(context.Background(), req, resp)

			if tc.wantErr && !resp.Diagnostics.HasError() {
				t.Error("expected error, got none")
			}
			if !tc.wantErr && resp.Diagnostics.HasError() {
				t.Errorf("expected no error, got: %v", resp.Diagnostics.Errors())
			}
		})
	}
}
