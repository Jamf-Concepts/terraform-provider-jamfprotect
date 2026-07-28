// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computeractions

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type durationValidator struct{}

// Duration returns a validator that checks whether a string value parses as a
// Go duration, such as "15m" or "1h30m".
func Duration() validator.String {
	return durationValidator{}
}

// Description describes the validation the validator applies.
func (v durationValidator) Description(_ context.Context) string {
	return "value must be a valid duration"
}

// MarkdownDescription describes the validation in Markdown.
func (v durationValidator) MarkdownDescription(_ context.Context) string {
	return "value must be a valid duration (for example `30s`, `15m`, `1h30m`)"
}

// ValidateString rejects values that do not parse as a positive Go duration.
func (v durationValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	parsed, err := time.ParseDuration(value)
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Duration",
			fmt.Sprintf("Value %q is not a valid duration. Use a Go duration string such as \"30s\", \"15m\" or \"1h30m\".", value),
		)
		return
	}
	if parsed <= 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Duration",
			fmt.Sprintf("Value %q must be greater than zero.", value),
		)
	}
}
