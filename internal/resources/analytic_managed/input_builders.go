// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// buildInternalInput converts the Terraform model into the InternalAnalyticInput payload
// used by the updateInternalAnalytic mutation. Only tenant_actions and tenant_severity are sent.
func (r *AnalyticManagedResource) buildInternalInput(ctx context.Context, data AnalyticManagedResourceModel, diags *diag.Diagnostics) *jamfprotect.InternalAnalyticInput {
	input := &jamfprotect.InternalAnalyticInput{}

	if !data.TenantSeverity.IsNull() && !data.TenantSeverity.IsUnknown() {
		input.TenantSeverity = data.TenantSeverity.ValueString()
	}

	if !data.TenantActions.IsNull() && !data.TenantActions.IsUnknown() {
		var actionModels []tenantActionModel
		diags.Append(data.TenantActions.ElementsAs(ctx, &actionModels, false)...)
		if diags.HasError() {
			return nil
		}

		actions := make([]jamfprotect.AnalyticActionInput, 0, len(actionModels))
		for _, a := range actionModels {
			paramJSON := "{}"
			if !a.Parameters.IsNull() && !a.Parameters.IsUnknown() {
				paramMap := map[string]string{}
				diags.Append(a.Parameters.ElementsAs(ctx, &paramMap, false)...)
				if diags.HasError() {
					return nil
				}
				if len(paramMap) > 0 {
					b, err := json.Marshal(paramMap)
					if err != nil {
						diags.AddError("Error encoding tenant action parameters", err.Error())
						return nil
					}
					paramJSON = string(b)
				}
			}
			actions = append(actions, jamfprotect.AnalyticActionInput{
				Name:       a.Name.ValueString(),
				Parameters: paramJSON,
			})
		}
		input.TenantActions = actions
	}

	return input
}
