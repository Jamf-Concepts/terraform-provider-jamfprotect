package change_management

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// apiToState maps the API response into the Terraform state model.
func (r *ChangeManagementResource) apiToState(_ context.Context, data *ChangeManagementResourceModel, api jamfprotect.ChangeManagementConfig) {
	data.ID = types.StringValue(changeManagementResourceID)
	data.EnableFreeze = types.BoolValue(api.ConfigFreeze)
}
