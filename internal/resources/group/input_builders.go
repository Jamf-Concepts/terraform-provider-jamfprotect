package group

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// buildGroupInput builds the API input from the Terraform model.
func buildGroupInput(ctx context.Context, data GroupResourceModel, diags *diag.Diagnostics) jamfprotect.GroupInput {
	input := jamfprotect.GroupInput{
		Name:    data.Name.ValueString(),
		RoleIDs: common.SetToStrings(ctx, data.RoleIDs, diags),
	}

	return input
}
