package role

import (
	"context"
	"fmt"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ValidateConfig validates role configuration inputs.
func (r *RoleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data RoleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.ReadPermissions.IsNull() || data.ReadPermissions.IsUnknown() {
		return
	}

	readValues := common.SetToStrings(ctx, data.ReadPermissions, &resp.Diagnostics)
	writeValues := common.SetToStrings(ctx, data.WritePermissions, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	readAPI := rolePermissionListToAPI(readValues, &resp.Diagnostics, "read_permissions")
	writeAPI := rolePermissionListToAPI(writeValues, &resp.Diagnostics, "write_permissions")
	if resp.Diagnostics.HasError() {
		return
	}

	if len(readAPI) == 0 {
		resp.Diagnostics.AddError(
			"Missing read permissions",
			"read_permissions must include at least one permission.",
		)
		return
	}

	readHasAll := rolePermissionHasAll(readAPI)
	writeHasAll := rolePermissionHasAll(writeAPI)
	if readHasAll && len(readAPI) > 1 {
		resp.Diagnostics.AddError(
			"Invalid read permissions",
			"read_permissions cannot include additional permissions when 'all' is set.",
		)
	}
	if writeHasAll && len(writeAPI) > 1 {
		resp.Diagnostics.AddError(
			"Invalid write permissions",
			"write_permissions cannot include additional permissions when 'all' is set.",
		)
	}
	if writeHasAll && !readHasAll {
		resp.Diagnostics.AddError(
			"Invalid write permissions",
			"write_permissions includes 'all' but read_permissions does not.",
		)
	}

	if !readHasAll {
		readSet := make(map[string]struct{}, len(readAPI))
		for _, value := range readAPI {
			readSet[value] = struct{}{}
		}

		for _, value := range writeAPI {
			if _, ok := readSet[value]; !ok {
				resp.Diagnostics.AddError(
					"Invalid write permissions",
					"write_permissions must be a subset of read_permissions.",
				)
				break
			}
		}

		for permission, dependencies := range rolePermissionDependencies {
			if _, ok := readSet[permission]; !ok {
				continue
			}
			for _, dependency := range dependencies {
				if _, ok := readSet[dependency]; !ok {
					resp.Diagnostics.AddError(
						"Missing required read permission",
						fmt.Sprintf("read_permissions requires %q when %q is set.", rolePermissionLabel(dependency), rolePermissionLabel(permission)),
					)
					break
				}
			}
		}
	}
}
