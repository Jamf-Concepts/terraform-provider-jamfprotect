// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// buildGroupInput builds the API input from the Terraform model.
func buildGroupInput(ctx context.Context, data GroupResourceModel, diags *diag.Diagnostics) jamfprotect.GroupInput {
	input := jamfprotect.GroupInput{
		Name:    data.Name.ValueString(),
		RoleIDs: common.SetToStrings(ctx, data.RoleIDs, diags),
	}

	return input
}
