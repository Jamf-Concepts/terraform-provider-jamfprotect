package exception_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
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

	exceptions, esExceptions := buildExceptionsInput(ctx, data.Exceptions, diags)
	if diags.HasError() {
		return nil
	}
	input.Exceptions = exceptions
	input.EsExceptions = esExceptions

	return input
}

// buildExceptionsInput converts exception models to API inputs.
func buildExceptionsInput(ctx context.Context, set types.Set, diags *diag.Diagnostics) ([]jamfprotect.ExceptionInput, []jamfprotect.EsExceptionInput) {
	if set.IsNull() || set.IsUnknown() {
		return []jamfprotect.ExceptionInput{}, []jamfprotect.EsExceptionInput{}
	}

	var exceptions []exceptionModel
	diags.Append(set.ElementsAs(ctx, &exceptions, false)...)
	if diags.HasError() {
		return nil, nil
	}

	standard := make([]jamfprotect.ExceptionInput, 0)
	es := make([]jamfprotect.EsExceptionInput, 0)
	for _, exc := range exceptions {
		exceptionType := exc.Type.ValueString()
		subType := ""
		if !exc.SubType.IsNull() && !exc.SubType.IsUnknown() {
			subType = exc.SubType.ValueString()
		}

		if exc.Rules.IsNull() || exc.Rules.IsUnknown() {
			continue
		}

		var rules []exceptionRuleModel
		diags.Append(exc.Rules.ElementsAs(ctx, &rules, false)...)
		if diags.HasError() {
			return nil, nil
		}

		if isEsExceptionType(exceptionType) {
			ignoreActivity, ignoreListType, ignoreListSubType, eventType, ok := mapEsExceptionSubType(exceptionType, subType)
			if !ok {
				diags.AddError(
					"Unsupported exception subtype",
					"No ES mapping found for exception type and subtype combination.",
				)
				return nil, nil
			}
			for _, rule := range rules {
				item := jamfprotect.EsExceptionInput{
					Type:           mapEsRuleTypeUIToAPI(rule.RuleType.ValueString(), diags),
					IgnoreActivity: ignoreActivity,
				}
				if diags.HasError() {
					return nil, nil
				}
				item.IgnoreListType = ignoreListType
				if ignoreListSubType != "" {
					item.IgnoreListSubType = ignoreListSubType
				}
				if eventType != "" {
					item.EventType = eventType
				}

				if rule.RuleType.ValueString() == "App Signing Info" {
					item.AppSigningInfo = buildAppSigningInfo(rule, diags)
					if diags.HasError() {
						return nil, nil
					}
				} else if !rule.Value.IsNull() && !rule.Value.IsUnknown() {
					item.Value = rule.Value.ValueString()
				}

				es = append(es, item)
			}
			continue
		}

		ignoreActivity, ok := exceptionTypeActivity(exceptionType)
		if !ok {
			diags.AddError(
				"Unsupported exception type",
				"No mapping found for exception type.",
			)
			return nil, nil
		}

		analyticTypes, hasAnalyticTypes := exceptionTypeAnalyticTypes(exceptionType)
		for _, rule := range rules {
			item := jamfprotect.ExceptionInput{
				Type:           mapRuleTypeUIToAPI(rule.RuleType.ValueString(), diags),
				IgnoreActivity: ignoreActivity,
			}
			if diags.HasError() {
				return nil, nil
			}
			if hasAnalyticTypes {
				item.AnalyticTypes = analyticTypes
			}
			if exceptionType == "Ignore for Analytic" {
				item.AnalyticUuid = subType
			}
			if rule.RuleType.ValueString() == "App Signing Info" {
				item.AppSigningInfo = buildAppSigningInfo(rule, diags)
				if diags.HasError() {
					return nil, nil
				}
			} else if !rule.Value.IsNull() && !rule.Value.IsUnknown() {
				item.Value = rule.Value.ValueString()
			}
			standard = append(standard, item)
		}
	}

	return standard, es
}

// buildAppSigningInfo builds AppSigningInfo input from rule data.
func buildAppSigningInfo(rule exceptionRuleModel, diags *diag.Diagnostics) *jamfprotect.AppSigningInfoInput {
	if rule.AppID.IsNull() || rule.AppID.IsUnknown() || rule.TeamID.IsNull() || rule.TeamID.IsUnknown() {
		diags.AddError(
			"Invalid App Signing Info rule",
			"App Signing Info rules require both app_id and team_id.",
		)
		return nil
	}
	return &jamfprotect.AppSigningInfoInput{
		AppId:  rule.AppID.ValueString(),
		TeamId: rule.TeamID.ValueString(),
	}
}
