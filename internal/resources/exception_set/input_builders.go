// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// buildInput converts the Terraform model into the service input.
func (r *ExceptionSetResource) buildInput(ctx context.Context, data ExceptionSetResourceModel, diags *diag.Diagnostics) *jamfprotect.ExceptionSetInput {
	input := &jamfprotect.ExceptionSetInput{
		Name: data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	input.Exceptions = buildExceptionsInput(ctx, data.Exceptions, diags)
	if diags.HasError() {
		return nil
	}

	input.EsExceptions = buildEsExceptionsInput(ctx, data.EsExceptions, diags)
	if diags.HasError() {
		return nil
	}

	return input
}

// buildExceptionsInput converts exception models to API inputs.
func buildExceptionsInput(ctx context.Context, set types.Set, diags *diag.Diagnostics) []jamfprotect.ExceptionInput {
	if set.IsNull() || set.IsUnknown() {
		return []jamfprotect.ExceptionInput{}
	}

	var exceptions []exceptionModel
	diags.Append(set.ElementsAs(ctx, &exceptions, false)...)
	if diags.HasError() {
		return nil
	}

	result := make([]jamfprotect.ExceptionInput, 0, len(exceptions))
	for _, exc := range exceptions {
		item := jamfprotect.ExceptionInput{
			Type:           mapExceptionTypeUIToAPI(exc.Type.ValueString(), diags),
			IgnoreActivity: exc.IgnoreActivity.ValueString(),
		}
		if diags.HasError() {
			return nil
		}

		if !exc.Value.IsNull() && !exc.Value.IsUnknown() {
			item.Value = exc.Value.ValueString()
		}

		if !exc.AppID.IsNull() && !exc.AppID.IsUnknown() && !exc.TeamID.IsNull() && !exc.TeamID.IsUnknown() {
			item.AppSigningInfo = &jamfprotect.AppSigningInfoInput{
				AppId:  exc.AppID.ValueString(),
				TeamId: exc.TeamID.ValueString(),
			}
		}

		if !exc.AnalyticTypes.IsNull() && !exc.AnalyticTypes.IsUnknown() {
			item.AnalyticTypes = common.SetToStrings(ctx, exc.AnalyticTypes, diags)
		}

		if !exc.AnalyticUuid.IsNull() && !exc.AnalyticUuid.IsUnknown() {
			item.AnalyticUuid = exc.AnalyticUuid.ValueString()
		}

		result = append(result, item)
	}

	return result
}

// buildEsExceptionsInput converts endpoint security exception models to API inputs.
func buildEsExceptionsInput(ctx context.Context, set types.Set, diags *diag.Diagnostics) []jamfprotect.EsExceptionInput {
	if set.IsNull() || set.IsUnknown() {
		return []jamfprotect.EsExceptionInput{}
	}

	var esExceptions []esExceptionModel
	diags.Append(set.ElementsAs(ctx, &esExceptions, false)...)
	if diags.HasError() {
		return nil
	}

	result := make([]jamfprotect.EsExceptionInput, 0, len(esExceptions))
	for _, exc := range esExceptions {
		item := jamfprotect.EsExceptionInput{
			Type:           mapEsExceptionTypeUIToAPI(exc.Type.ValueString(), diags),
			IgnoreActivity: exc.IgnoreActivity.ValueString(),
		}
		if diags.HasError() {
			return nil
		}

		if !exc.Value.IsNull() && !exc.Value.IsUnknown() {
			item.Value = exc.Value.ValueString()
		}

		if !exc.IgnoreListType.IsNull() && !exc.IgnoreListType.IsUnknown() {
			item.IgnoreListType = exc.IgnoreListType.ValueString()
		}
		if !exc.IgnoreListSubType.IsNull() && !exc.IgnoreListSubType.IsUnknown() {
			item.IgnoreListSubType = exc.IgnoreListSubType.ValueString()
		}
		if !exc.EventType.IsNull() && !exc.EventType.IsUnknown() {
			item.EventType = exc.EventType.ValueString()
		}

		if !exc.AppID.IsNull() && !exc.AppID.IsUnknown() && !exc.TeamID.IsNull() && !exc.TeamID.IsUnknown() {
			item.AppSigningInfo = &jamfprotect.AppSigningInfoInput{
				AppId:  exc.AppID.ValueString(),
				TeamId: exc.TeamID.ValueString(),
			}
		}

		result = append(result, item)
	}

	return result
}
