// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package api_client

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// buildApiClientInput builds the API input from the Terraform model.
func buildApiClientInput(ctx context.Context, data ApiClientResourceModel, diags *diag.Diagnostics) jamfprotect.ApiClientInput {
	return jamfprotect.ApiClientInput{
		Name:    data.Name.ValueString(),
		RoleIDs: common.SetToStrings(ctx, data.RoleIDs, diags),
	}
}
