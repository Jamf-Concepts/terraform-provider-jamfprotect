package exception_set

import (
	"context"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ list.ListResource = &ExceptionSetListResource{}
var _ list.ListResourceWithConfigure = &ExceptionSetListResource{}
var _ list.ListResourceWithValidateConfig = &ExceptionSetListResource{}

// ExceptionSetListResource lists exception sets in Jamf Protect.
type ExceptionSetListResource struct {
	service *jamfprotect.Service
}

// listConfigModel maps list resource configuration.

// NewExceptionSetListResource instantiates the exception set list resource.
func NewExceptionSetListResource() list.ListResource {
	return &ExceptionSetListResource{}
}

// Metadata sets the list resource type name.
func (r *ExceptionSetListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_exception_set"
}

// ListResourceConfigSchema defines the list configuration schema.
func (r *ExceptionSetListResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Lists exception sets in Jamf Protect.",
		Attributes: map[string]listschema.Attribute{
			"name_prefix": listschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional name prefix filter applied to listed exception sets.",
			},
		},
	}
}

// Configure assigns the Jamf Protect client for list operations.
func (r *ExceptionSetListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

// ValidateListResourceConfig validates list configuration inputs.
func (r *ExceptionSetListResource) ValidateListResourceConfig(ctx context.Context, req list.ValidateConfigRequest, resp *list.ValidateConfigResponse) {
	var config common.ListConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	common.ValidateNamePrefix(config, &resp.Diagnostics)
}

// List streams exception set list results.
func (r *ExceptionSetListResource) List(ctx context.Context, req list.ListRequest, resp *list.ListResultsStream) {
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

	items, err := r.service.ListExceptionSets(ctx)
	if err != nil {
		resp.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{
			diag.NewErrorDiagnostic("Error listing exception sets", err.Error()),
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
			api, err := r.service.GetExceptionSet(ctx, item.UUID)
			if err != nil {
				result.Diagnostics.AddError("Error reading exception set", err.Error())
				results = append(results, result)
				continue
			}
			if api == nil {
				result.Diagnostics.AddError(
					"Exception set missing",
					"The list response referenced an exception set that no longer exists.",
				)
				results = append(results, result)
				continue
			}

			var data ExceptionSetResourceModel
			stateBuilder := ExceptionSetResource{}
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
