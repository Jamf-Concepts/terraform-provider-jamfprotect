// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// buildInput converts the Terraform model into the service input. priorActions holds the
// analytic's current actions (null on create); actions other than SmartGroup are carried over
// from it, and the SmartGroup action follows the Smart Group attributes.
func (r *AnalyticResource) buildInput(ctx context.Context, data AnalyticResourceModel, priorActions types.List, diags *diag.Diagnostics) *jamfprotect.AnalyticInput {
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

	actions := mergeSmartGroupAction(ctx, priorActions, smartGroupAction(data.AddToJamfProSmartGroup, data.JamfProSmartGroupIdentifier), diags)
	if diags.HasError() {
		return nil
	}
	input.AnalyticActions = analyticActionsToInput(ctx, actions, diags)
	if diags.HasError() {
		return nil
	}

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
