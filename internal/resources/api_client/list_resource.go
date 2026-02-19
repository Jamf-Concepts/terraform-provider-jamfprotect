// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package api_client

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ list.ListResource = &ApiClientListResource{}
var _ list.ListResourceWithConfigure = &ApiClientListResource{}
var _ list.ListResourceWithValidateConfig = &ApiClientListResource{}

// NewApiClientListResource returns a new API client list resource.
func NewApiClientListResource() list.ListResource {
	return &ApiClientListResource{}
}

// ApiClientListResource lists API clients in Jamf Protect.
type ApiClientListResource struct {
	service *jamfprotect.Service
}

// listConfigModel maps list configuration for API client list resources.
type listConfigModel struct {
	NamePrefix types.String `tfsdk:"name_prefix"`
}

func (r *ApiClientListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_client"
}

func (r *ApiClientListResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Lists API clients in Jamf Protect.",
		Attributes: map[string]listschema.Attribute{
			"name_prefix": listschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional name prefix filter applied to listed API clients.",
			},
		},
	}
}

func (r *ApiClientListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected List Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	r.service = jamfprotect.NewService(client)
}

func (r *ApiClientListResource) ValidateListResourceConfig(ctx context.Context, req list.ValidateConfigRequest, resp *list.ValidateConfigResponse) {
	var config listConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.NamePrefix.IsNull() && !config.NamePrefix.IsUnknown() && strings.TrimSpace(config.NamePrefix.ValueString()) == "" {
		resp.Diagnostics.AddError(
			"Invalid name_prefix",
			"name_prefix must not be empty when set.",
		)
	}
}

func (r *ApiClientListResource) List(ctx context.Context, req list.ListRequest, resp *list.ListResultsStream) {
	if r.service == nil {
		resp.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"Missing Jamf Protect client",
				"The provider client was not configured for list resources.",
			),
		})
		return
	}

	var config listConfigModel
	configDiags := req.Config.Get(ctx, &config)
	if configDiags.HasError() {
		resp.Results = list.ListResultsStreamDiagnostics(configDiags)
		return
	}

	items, err := r.service.ListApiClients(ctx)
	if err != nil {
		resp.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{
			diag.NewErrorDiagnostic("Error listing API clients", err.Error()),
		})
		return
	}

	prefix := ""
	if !config.NamePrefix.IsNull() && !config.NamePrefix.IsUnknown() {
		prefix = config.NamePrefix.ValueString()
	}

	results := make([]list.ListResult, 0, len(items))
	for _, item := range items {
		if prefix != "" && !strings.HasPrefix(item.Name, prefix) {
			continue
		}
		if req.Limit > 0 && int64(len(results)) >= req.Limit {
			break
		}

		result := req.NewListResult(ctx)
		result.DisplayName = item.Name
		result.Diagnostics.Append(result.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(item.ClientID))...)
		if result.Diagnostics.HasError() {
			results = append(results, result)
			continue
		}

		if req.IncludeResource {
			api, err := r.service.GetApiClient(ctx, item.ClientID)
			if err != nil {
				result.Diagnostics.AddError("Error reading API client", err.Error())
				results = append(results, result)
				continue
			}
			if api == nil {
				result.Diagnostics.AddError(
					"API client missing",
					"The list response referenced an API client that no longer exists.",
				)
				results = append(results, result)
				continue
			}

			var data ApiClientResourceModel
			stateBuilder := ApiClientResource{}
			stateBuilder.apiToState(ctx, &data, *api)
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
