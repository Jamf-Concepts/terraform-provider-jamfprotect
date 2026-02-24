// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ list.ListResource = &ActionConfigListResource{}
var _ list.ListResourceWithConfigure = &ActionConfigListResource{}
var _ list.ListResourceWithValidateConfig = &ActionConfigListResource{}

func NewActionConfigListResource() list.ListResource {
	return &ActionConfigListResource{}
}

// ActionConfigListResource lists action configurations in Jamf Protect.
type ActionConfigListResource struct {
	service *jamfprotect.Service
}

func (r *ActionConfigListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_action_configuration"
}

func (r *ActionConfigListResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Lists Action Configurations in Jamf Protect.",
		Attributes: map[string]listschema.Attribute{
			"name_prefix": listschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional name prefix filter applied to listed Action Configurations.",
			},
		},
	}
}

func (r *ActionConfigListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (r *ActionConfigListResource) ValidateListResourceConfig(ctx context.Context, req list.ValidateConfigRequest, resp *list.ValidateConfigResponse) {
	var config common.ListConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	common.ValidateNamePrefix(config, &resp.Diagnostics)
}

func (r *ActionConfigListResource) List(ctx context.Context, req list.ListRequest, resp *list.ListResultsStream) {
	if r.service == nil {
		resp.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"Missing Jamf Protect client",
				"The provider client was not configured for list resources.",
			),
		})
		return
	}

	var config common.ListConfigModel
	configDiags := req.Config.Get(ctx, &config)
	if configDiags.HasError() {
		resp.Results = list.ListResultsStreamDiagnostics(configDiags)
		return
	}

	items, err := r.service.ListActionConfigs(ctx)
	if err != nil {
		resp.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{
			diag.NewErrorDiagnostic("Error listing action configs", err.Error()),
		})
		return
	}

	results := make([]list.ListResult, 0, len(items))
	for _, item := range items {
		if !common.MatchesNamePrefix(config, item.Name) {
			continue
		}
		if req.Limit > 0 && int64(len(results)) >= req.Limit {
			break
		}

		result := req.NewListResult(ctx)
		result.DisplayName = item.Name
		result.Diagnostics.Append(result.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(item.ID))...)
		if result.Diagnostics.HasError() {
			results = append(results, result)
			continue
		}

		if req.IncludeResource {
			api, err := r.service.GetActionConfig(ctx, item.ID)
			if err != nil {
				result.Diagnostics.AddError("Error reading action config", err.Error())
				results = append(results, result)
				continue
			}
			if api == nil {
				result.Diagnostics.AddError(
					"Action config missing",
					"The list response referenced an action configuration that no longer exists.",
				)
				results = append(results, result)
				continue
			}

			var data ActionConfigResourceModel
			stateBuilder := ActionConfigResource{}
			stateBuilder.applyState(ctx, &data, *api, &result.Diagnostics)
			if result.Diagnostics.HasError() {
				results = append(results, result)
				continue
			}
			data.Timeouts = common.EmptyTimeoutsValue()
			result.Diagnostics.Append(result.Resource.Set(ctx, &data)...)
			results = append(results, result)
			continue
		}

		result.Resource = nil
		results = append(results, result)
	}

	resp.Results = slices.Values(results)
}
