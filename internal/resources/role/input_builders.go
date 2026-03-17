// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package role

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// buildRoleInput builds the API input from the Terraform model.
func buildRoleInput(ctx context.Context, data RoleResourceModel, diags *diag.Diagnostics) jamfprotect.RoleInput {
	readValues := common.SetToStrings(ctx, data.ReadPermissions, diags)
	writeValues := common.SetToStrings(ctx, data.WritePermissions, diags)
	if diags.HasError() {
		return jamfprotect.RoleInput{}
	}

	readAPI := rolePermissionListToAPI(readValues, diags, "read_permissions")
	writeAPI := rolePermissionListToAPI(writeValues, diags, "write_permissions")
	if diags.HasError() {
		return jamfprotect.RoleInput{}
	}

	if rolePermissionHasAll(readAPI) {
		readAPI = []string{"all"}
	}
	if rolePermissionHasAll(writeAPI) {
		writeAPI = []string{"all"}
	}

	if !rolePermissionHasAll(readAPI) {
		readAPI = rolePermissionAddHiddenException(readAPI)
	}
	if !rolePermissionHasAll(writeAPI) {
		writeAPI = rolePermissionAddHiddenException(writeAPI)
	}

	if len(readAPI) == 0 {
		readAPI = []string{}
	}
	if len(writeAPI) == 0 {
		writeAPI = []string{}
	}

	return jamfprotect.RoleInput{
		Name:           data.Name.ValueString(),
		ReadResources:  readAPI,
		WriteResources: writeAPI,
	}
}

// rolePermissionAddHiddenException ensures Exception is included when Exception Sets is present.
func rolePermissionAddHiddenException(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	if _, ok := seen["ExceptionSet"]; !ok {
		return values
	}
	if _, ok := seen["Exception"]; ok {
		return values
	}
	return append(values, "Exception")
}
