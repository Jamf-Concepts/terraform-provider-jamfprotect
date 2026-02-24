// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type uuidValidator struct{}

// UUID returns a validator that checks whether a string value is a valid UUID.
func UUID() validator.String {
	return uuidValidator{}
}

func (v uuidValidator) Description(_ context.Context) string {
	return "value must be a valid UUID"
}

func (v uuidValidator) MarkdownDescription(_ context.Context) string {
	return "value must be a valid UUID (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)"
}

func (v uuidValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if _, err := uuid.ParseUUID(value); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid UUID Format",
			fmt.Sprintf("Value %q is not a valid UUID. Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", value),
		)
	}
}
