package validators

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type resourceNameValidator struct{}

// ResourceName returns a validator that checks whether a string value is a valid
// resource name: between 1 and 255 characters with no leading or trailing whitespace.
func ResourceName() validator.String {
	return resourceNameValidator{}
}

func (v resourceNameValidator) Description(_ context.Context) string {
	return "must be 1-255 characters with no leading or trailing whitespace"
}

func (v resourceNameValidator) MarkdownDescription(_ context.Context) string {
	return "must be 1-255 characters with no leading or trailing whitespace"
}

func (v resourceNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()

	if len(value) == 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Resource Name",
			"Name must not be empty.",
		)
		return
	}

	if len(value) > 255 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Resource Name",
			fmt.Sprintf("Name must be at most 255 characters, got %d.", len(value)),
		)
		return
	}

	if strings.TrimSpace(value) != value {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Resource Name",
			"Name must not have leading or trailing whitespace.",
		)
	}
}
