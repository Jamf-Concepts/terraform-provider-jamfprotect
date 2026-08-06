// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set

import (
	"context"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ list.ListResource = &UnifiedLoggingFilterSetListResource{}
var _ list.ListResourceWithConfigure = &UnifiedLoggingFilterSetListResource{}
var _ list.ListResourceWithValidateConfig = &UnifiedLoggingFilterSetListResource{}

// NewUnifiedLoggingFilterSetListResource instantiates the unified logging filter set list resource.
func NewUnifiedLoggingFilterSetListResource() list.ListResource {
	return &UnifiedLoggingFilterSetListResource{}
}

// UnifiedLoggingFilterSetListResource lists unified logging filter sets in Jamf Protect.
type UnifiedLoggingFilterSetListResource struct {
	client *jamfprotect.Client
}

// Metadata sets the list resource type name.
func (r *UnifiedLoggingFilterSetListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_unified_logging_filter_set"
}

// ListResourceConfigSchema defines the list configuration schema.
func (r *UnifiedLoggingFilterSetListResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Lists unified logging filter sets in Jamf Protect.",
		Attributes: map[string]listschema.Attribute{
			"name_prefix": listschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional name prefix filter applied to listed unified logging filter sets.",
			},
			"exclude_builtins": common.ExcludeBuiltinsSchemaAttribute(),
		},
	}
}

// Configure assigns the Jamf Protect client for list operations.
func (r *UnifiedLoggingFilterSetListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// ValidateListResourceConfig validates list configuration inputs.
func (r *UnifiedLoggingFilterSetListResource) ValidateListResourceConfig(ctx context.Context, req list.ValidateConfigRequest, resp *list.ValidateConfigResponse) {
	var config common.ListConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	common.ValidateNamePrefix(config, &resp.Diagnostics)
}

// List streams unified logging filter set list results.
func (r *UnifiedLoggingFilterSetListResource) List(ctx context.Context, req list.ListRequest, resp *list.ListResultsStream) {
	if r.client == nil {
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

	items, err := r.client.ListUnifiedLoggingFilterSets(ctx)
	if err != nil {
		resp.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{
			diag.NewErrorDiagnostic("Error listing unified logging filter sets", err.Error()),
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
		result.Diagnostics.Append(result.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(item.UUID))...)
		if result.Diagnostics.HasError() {
			results = append(results, result)
			continue
		}

		if req.IncludeResource {
			api, err := r.client.GetUnifiedLoggingFilterSet(ctx, item.UUID)
			if err != nil {
				result.Diagnostics.AddError("Error reading unified logging filter set", err.Error())
				results = append(results, result)
				continue
			}
			if api == nil {
				result.Diagnostics.AddError(
					"Unified logging filter set missing",
					"The list response referenced a filter set that no longer exists.",
				)
				results = append(results, result)
				continue
			}

			var data UnifiedLoggingFilterSetResourceModel
			stateBuilder := UnifiedLoggingFilterSetResource{}
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
