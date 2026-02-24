package group

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// apiToState maps the API response into the Terraform state model.
func (r *GroupResource) apiToState(_ context.Context, data *GroupResourceModel, api jamfprotect.Group) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	roleIDs := common.MapSlice(api.AssignedRoles, func(r jamfprotect.GroupRole) string { return r.ID })
	if len(roleIDs) == 0 && (data.RoleIDs.IsNull() || data.RoleIDs.IsUnknown()) {
		data.RoleIDs = types.SetNull(types.StringType)
	} else {
		data.RoleIDs = common.StringsToSet(roleIDs)
	}

}

// groupAPIToDataSourceItem maps API group data to a data source item.
func groupAPIToDataSourceItem(api jamfprotect.Group) GroupDataSourceItemModel {
	item := GroupDataSourceItemModel{
		ID:      types.StringValue(api.ID),
		Name:    types.StringValue(api.Name),
		Created: types.StringValue(api.Created),
		Updated: types.StringValue(api.Updated),
		RoleIDs: common.SortedStringsToList(common.MapSlice(api.AssignedRoles, func(r jamfprotect.GroupRole) string { return r.ID })),
	}

	return item
}
