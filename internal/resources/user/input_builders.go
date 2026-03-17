// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package user

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// buildUserInput builds the API input from the Terraform model.
func buildUserInput(ctx context.Context, data UserResourceModel, diags *diag.Diagnostics) jamfprotect.UserInput {
	input := jamfprotect.UserInput{
		Email:                 data.Email.ValueString(),
		RoleIDs:               common.SetToStrings(ctx, data.RoleIDs, diags),
		GroupIDs:              common.SetToStrings(ctx, data.GroupIDs, diags),
		ReceiveEmailAlert:     data.SendEmailNotifications.ValueBool(),
		EmailAlertMinSeverity: data.EmailSeverity.ValueString(),
	}

	if common.HasStringValue(data.IdentityProviderID) {
		input.ConnectionID = new(data.IdentityProviderID.ValueString())
	}

	return input
}
