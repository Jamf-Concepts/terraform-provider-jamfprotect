// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package api_client

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// apiToState maps the API response into the Terraform state model.
func (r *ApiClientResource) apiToState(_ context.Context, data *ApiClientResourceModel, api jamfprotect.ApiClient) {
	data.ID = types.StringValue(api.ClientID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Password = apiClientPasswordStateValue(data.Password, api.Password)

	roleIDs := apiClientRoleIDs(api.AssignedRoles)
	if len(roleIDs) == 0 && (data.RoleIDs.IsNull() || data.RoleIDs.IsUnknown()) {
		data.RoleIDs = types.SetNull(types.StringType)
	} else {
		data.RoleIDs = common.StringsToSet(roleIDs)
	}
}

// apiClientRoleIDs extracts role IDs from API roles.
func apiClientRoleIDs(roles []jamfprotect.ApiClientRole) []string {
	if len(roles) == 0 {
		return nil
	}
	ids := make([]string, 0, len(roles))
	for _, role := range roles {
		ids = append(ids, role.ID)
	}
	return ids
}

// apiClientPasswordStateValue preserves an existing password when the API returns a masked value.
func apiClientPasswordStateValue(current types.String, password string) types.String {
	if password == "" || password == apiClientPasswordMask {
		if common.IsKnownString(current) {
			return current
		}
		return types.StringNull()
	}
	return types.StringValue(password)
}

// apiClientPasswordDataSourceValue maps the API password into a data source-friendly value.
func apiClientPasswordDataSourceValue(password string) types.String {
	if password == "" || password == apiClientPasswordMask {
		return types.StringNull()
	}
	return types.StringValue(password)
}

// apiClientAPIToDataSourceItem maps API client data to a data source item.
func apiClientAPIToDataSourceItem(api jamfprotect.ApiClient) ApiClientDataSourceItemModel {
	return ApiClientDataSourceItemModel{
		ID:       types.StringValue(api.ClientID),
		Name:     types.StringValue(api.Name),
		RoleIDs:  common.StringsToSet(apiClientRoleIDs(api.AssignedRoles)),
		Password: apiClientPasswordDataSourceValue(api.Password),
		Created:  types.StringValue(api.Created),
	}
}
