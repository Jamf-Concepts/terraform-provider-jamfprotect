// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computeractions

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestDurationValidator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		value   types.String
		wantErr bool
	}{
		{"null", types.StringNull(), false},
		{"unknown", types.StringUnknown(), false},
		{"minutes", types.StringValue("15m"), false},
		{"compound", types.StringValue("1h30m"), false},
		{"not a duration", types.StringValue("soon"), true},
		{"bare number", types.StringValue("15"), true},
		{"zero", types.StringValue("0s"), true},
		{"negative", types.StringValue("-5m"), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			req := validator.StringRequest{Path: path.Root("timeout"), ConfigValue: c.value}
			var resp validator.StringResponse
			Duration().ValidateString(context.Background(), req, &resp)

			if got := resp.Diagnostics.HasError(); got != c.wantErr {
				t.Errorf("hasError = %v, want %v (diags: %v)", got, c.wantErr, resp.Diagnostics)
			}
		})
	}
}
