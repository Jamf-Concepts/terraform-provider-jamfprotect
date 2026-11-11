// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// buildInput converts the Terraform model into the service input.
func (r *PreventListSetResource) buildInput(ctx context.Context, data PreventListSetResourceModel, diags *diag.Diagnostics) *jamfprotect.PreventListSetInput {
	input := &jamfprotect.PreventListSetInput{
		Name: data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	}

	lists := common.SetToStrings(ctx, data.PreventLists, diags)
	if diags.HasError() {
		return nil
	}
	if lists == nil {
		lists = []string{}
	}
	input.PreventLists = lists

	return input
}
