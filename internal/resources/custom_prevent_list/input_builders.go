// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"context"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// buildInput converts the Terraform model into the service input.
func (r *CustomPreventListResource) buildInput(ctx context.Context, data CustomPreventListResourceModel, diags *diag.Diagnostics) *jamfprotect.CustomPreventListInput {
	preventType := mapPreventTypeUIToAPI(data.PreventType.ValueString(), diags)
	if diags.HasError() {
		return nil
	}

	input := &jamfprotect.CustomPreventListInput{
		Name: data.Name.ValueString(),
		Type: preventType,
	}
	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}
	input.Tags = []string{}
	input.List = common.ListToStrings(ctx, data.ListData, diags)
	return input
}
