// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ validator.Set = additionalEventsValidator{}

// additionalEventsValidator rejects additional_events entries that a category attribute already collects.
type additionalEventsValidator struct{}

// Description describes the validator.
func (v additionalEventsValidator) Description(_ context.Context) string {
	return "events must not belong to a log_* category"
}

// MarkdownDescription describes the validator in Markdown.
func (v additionalEventsValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateSet reports an error for each element that belongs to a category.
func (v additionalEventsValidator) ValidateSet(_ context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	for _, element := range req.ConfigValue.Elements() {
		value, ok := element.(types.String)
		if !ok || value.IsNull() || value.IsUnknown() {
			continue
		}
		attribute, found := eventCategoryAttribute(value.ValueString())
		if !found {
			continue
		}
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Event belongs to a category",
			fmt.Sprintf("%q is collected by %s. Set %s = true instead of listing the event in additional_events.", value.ValueString(), attribute, attribute),
		)
	}
}
