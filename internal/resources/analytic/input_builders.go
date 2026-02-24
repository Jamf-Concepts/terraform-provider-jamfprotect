// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"encoding/json"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// buildInput converts the Terraform model into the service input.
func (r *AnalyticResource) buildInput(ctx context.Context, data AnalyticResourceModel, diags *diag.Diagnostics) *jamfprotect.AnalyticInput {
	sensorType := mapSensorTypeUIToAPI(data.SensorType.ValueString(), diags)
	if diags.HasError() {
		return nil
	}

	input := &jamfprotect.AnalyticInput{
		Name:      data.Name.ValueString(),
		InputType: sensorType,
		Filter:    data.Filter.ValueString(),
		Level:     data.Level.ValueInt64(),
		Severity:  data.Severity.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	input.Tags = common.SetToStrings(ctx, data.Tags, diags)
	input.Categories = common.SetToStrings(ctx, data.Categories, diags)
	input.SnapshotFiles = common.SetToStrings(ctx, data.SnapshotFiles, diags)

	actions := []jamfprotect.AnalyticActionInput{}
	if !data.AddToJamfProSmartGroup.IsNull() && data.AddToJamfProSmartGroup.ValueBool() {
		paramValue := "{}"
		if !data.JamfProSmartGroupIdentifier.IsNull() && data.JamfProSmartGroupIdentifier.ValueString() != "" {
			paramMap := map[string]string{"id": data.JamfProSmartGroupIdentifier.ValueString()}
			jsonBytes, err := json.Marshal(paramMap)
			if err != nil {
				diags.AddError("Error encoding Smart Group identifier", err.Error())
				return nil
			}
			paramValue = string(jsonBytes)
		}
		actions = append(actions, jamfprotect.AnalyticActionInput{
			Name:       "SmartGroup",
			Parameters: paramValue,
		})
	}
	input.AnalyticActions = actions

	var ctxEntries []jamfprotect.AnalyticContextInput
	if !data.ContextItem.IsNull() {
		var contextModels []analyticContextModel
		diags.Append(data.ContextItem.ElementsAs(ctx, &contextModels, false)...)
		for _, c := range contextModels {
			ctxEntries = append(ctxEntries, jamfprotect.AnalyticContextInput{
				Name:  c.Name.ValueString(),
				Type:  c.Type.ValueString(),
				Exprs: common.SetToStrings(ctx, c.Expressions, diags),
			})
		}
	}
	if ctxEntries == nil {
		ctxEntries = []jamfprotect.AnalyticContextInput{}
	}
	input.Context = ctxEntries

	return input
}
