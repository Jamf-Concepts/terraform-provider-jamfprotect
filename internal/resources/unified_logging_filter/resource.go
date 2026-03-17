// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/validators"
)

var _ resource.Resource = &UnifiedLoggingFilterResource{}
var _ resource.ResourceWithImportState = &UnifiedLoggingFilterResource{}
var _ resource.ResourceWithIdentity = &UnifiedLoggingFilterResource{}

// NewUnifiedLoggingFilterResource returns a new unified logging filter resource.
func NewUnifiedLoggingFilterResource() resource.Resource {
	return &UnifiedLoggingFilterResource{}
}

// UnifiedLoggingFilterResource manages a Jamf Protect unified logging filter.
type UnifiedLoggingFilterResource struct {
	client *jamfprotect.Client
}

// Metadata returns the unified logging filter resource type name.
func (r *UnifiedLoggingFilterResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_unified_logging_filter"
}

// Schema defines the unified logging filter schema.
func (r *UnifiedLoggingFilterResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a unified logging filter in Jamf Protect. Unified logging filters capture macOS unified log entries that match a given predicate.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the unified logging filter.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the unified logging filter.",
				Required:            true,
				Validators:          []validator.String{validators.ResourceName()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the unified logging filter.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"filter": schema.StringAttribute{
				MarkdownDescription: "The predicate filter expression (NSPredicate format).",
				Required:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the filter is enabled. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"tags": schema.SetAttribute{
				MarkdownDescription: "A set of tags for the unified logging filter.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last-updated timestamp.",
				Computed:            true,
			},
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

// IdentitySchema defines the identity attributes for unified logging filters.
func (r *UnifiedLoggingFilterResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the unified logging filter.",
			},
		},
	}
}

// Configure prepares the unified logging filter service client.
func (r *UnifiedLoggingFilterResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// ImportState supports importing unified logging filters by ID.
func (r *UnifiedLoggingFilterResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
