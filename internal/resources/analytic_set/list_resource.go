package analytic_set

import (
	"context"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ list.ListResource = &AnalyticSetListResource{}
var _ list.ListResourceWithConfigure = &AnalyticSetListResource{}
var _ list.ListResourceWithValidateConfig = &AnalyticSetListResource{}

func NewAnalyticSetListResource() list.ListResource {
	return &AnalyticSetListResource{}
}

// AnalyticSetListResource lists analytic sets in Jamf Protect.
type AnalyticSetListResource struct {
	service *jamfprotect.Service
}

func (r *AnalyticSetListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analytic_set"
}

func (r *AnalyticSetListResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Lists analytic sets in Jamf Protect.",
		Attributes: map[string]listschema.Attribute{
			"name_prefix": listschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional name prefix filter applied to listed analytic sets.",
			},
		},
	}
}

func (r *AnalyticSetListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (r *AnalyticSetListResource) ValidateListResourceConfig(ctx context.Context, req list.ValidateConfigRequest, resp *list.ValidateConfigResponse) {
	var config common.ListConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	common.ValidateNamePrefix(config, &resp.Diagnostics)
}

func (r *AnalyticSetListResource) List(ctx context.Context, req list.ListRequest, resp *list.ListResultsStream) {
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

	items, err := r.service.ListAnalyticSets(ctx)
	if err != nil {
		resp.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{
			diag.NewErrorDiagnostic("Error listing analytic sets", err.Error()),
		})
		return
	}

	prefix := ""
	if !config.NamePrefix.IsNull() && !config.NamePrefix.IsUnknown() {
		prefix = config.NamePrefix.ValueString()
	}

	results := make([]list.ListResult, 0, len(items))
	for _, item := range items {
		if isSystemAnalyticSetName(item.Name) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(item.Name, prefix) {
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
			api, err := r.service.GetAnalyticSet(ctx, item.UUID)
			if err != nil {
				result.Diagnostics.AddError("Error reading analytic set", err.Error())
				results = append(results, result)
				continue
			}
			if api == nil {
				result.Diagnostics.AddError(
					"Analytic set missing",
					"The list response referenced an analytic set that no longer exists.",
				)
				results = append(results, result)
				continue
			}

			var data AnalyticSetResourceModel
			stateBuilder := AnalyticSetResource{}
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
