// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package identity_provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// connectionAPIToDataSourceItem maps a Connection API response to a data source item model.
func connectionAPIToDataSourceItem(api jamfprotect.Connection) IdentityProviderDataSourceItemModel {
	return IdentityProviderDataSourceItemModel{
		ID:                types.StringValue(api.ID),
		Name:              types.StringValue(api.Name),
		RequireKnownUsers: types.BoolValue(api.RequireKnownUsers),
		Button:            types.StringValue(api.Button),
		Created:           types.StringValue(api.Created),
		Updated:           types.StringValue(api.Updated),
		Strategy:          types.StringValue(api.Strategy),
		GroupsSupport:     types.BoolValue(api.GroupsSupport),
		Source:            types.StringValue(api.Source),
	}
}
