// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package api_client

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// buildApiClientInput builds the API input from the Terraform model.
func buildApiClientInput(ctx context.Context, data ApiClientResourceModel, diags *diag.Diagnostics) jamfprotect.ApiClientInput {
	return jamfprotect.ApiClientInput{
		Name:    data.Name.ValueString(),
		RoleIDs: common.SetToStrings(ctx, data.RoleIDs, diags),
	}
}
