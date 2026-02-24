// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package user

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

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ list.ListResource = &UserListResource{}
var _ list.ListResourceWithConfigure = &UserListResource{}
var _ list.ListResourceWithValidateConfig = &UserListResource{}

// NewUserListResource returns a new user list resource.
func NewUserListResource() list.ListResource {
	return &UserListResource{}
}

// UserListResource lists users in Jamf Protect.
type UserListResource struct {
	service *jamfprotect.Service
}

type listConfigModel struct {
	EmailPrefix types.String `tfsdk:"email_prefix"`
}

func (r *UserListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *UserListResource) ListResourceConfigSchema(ctx context.Context, req list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Lists users in Jamf Protect.",
		Attributes: map[string]listschema.Attribute{
			"email_prefix": listschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional email prefix filter applied to listed users.",
			},
		},
	}
}

func (r *UserListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

func (r *UserListResource) ValidateListResourceConfig(ctx context.Context, req list.ValidateConfigRequest, resp *list.ValidateConfigResponse) {
	var config listConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.EmailPrefix.IsNull() && !config.EmailPrefix.IsUnknown() && strings.TrimSpace(config.EmailPrefix.ValueString()) == "" {
		resp.Diagnostics.AddError(
			"Invalid email_prefix",
			"email_prefix must not be empty when set.",
		)
	}
}

func (r *UserListResource) List(ctx context.Context, req list.ListRequest, resp *list.ListResultsStream) {
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

	items, err := r.service.ListUsers(ctx)
	if err != nil {
		resp.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{
			diag.NewErrorDiagnostic("Error listing users", err.Error()),
		})
		return
	}

	prefix := ""
	if !config.EmailPrefix.IsNull() && !config.EmailPrefix.IsUnknown() {
		prefix = config.EmailPrefix.ValueString()
	}

	results := make([]list.ListResult, 0, len(items))
	for _, item := range items {
		if prefix != "" && !strings.HasPrefix(item.Email, prefix) {
			continue
		}
		if req.Limit > 0 && int64(len(results)) >= req.Limit {
			break
		}

		result := req.NewListResult(ctx)
		result.DisplayName = item.Email
		result.Diagnostics.Append(result.Identity.SetAttribute(ctx, path.Root("id"), types.StringValue(item.ID))...)
		if result.Diagnostics.HasError() {
			results = append(results, result)
			continue
		}

		if req.IncludeResource {
			api, err := r.service.GetUser(ctx, item.ID)
			if err != nil {
				result.Diagnostics.AddError("Error reading user", err.Error())
				results = append(results, result)
				continue
			}
			if api == nil {
				result.Diagnostics.AddError(
					"User missing",
					"The list response referenced a user that no longer exists.",
				)
				results = append(results, result)
				continue
			}

			var data UserResourceModel
			stateBuilder := UserResource{}
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
