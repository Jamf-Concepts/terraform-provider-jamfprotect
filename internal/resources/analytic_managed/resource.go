// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ resource.Resource = &AnalyticManagedResource{}
var _ resource.ResourceWithImportState = &AnalyticManagedResource{}
var _ resource.ResourceWithIdentity = &AnalyticManagedResource{}

func NewAnalyticManagedResource() resource.Resource {
	return &AnalyticManagedResource{}
}

// AnalyticManagedResource manages tenant-scoped overrides on a Jamf-managed analytic.
// Jamf-managed analytics cannot be created or destroyed via Terraform — they must be imported.
// Updates are restricted to tenant_actions and tenant_severity via the updateInternalAnalytic mutation.
type AnalyticManagedResource struct {
	client *jamfprotect.Client
}

func (r *AnalyticManagedResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analytic_managed"
}

func (r *AnalyticManagedResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages tenant-scoped overrides on a Jamf-managed analytic in Jamf Protect. " +
			"Jamf-managed analytics are read-only at the global level — they cannot be created or destroyed via Terraform. " +
			"Bring an existing Jamf-managed analytic under management with `terraform import`. " +
			"Only `tenant_actions` and `tenant_severity` may be modified.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the Jamf-managed analytic.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the analytic (read-only — assigned by Jamf).",
				Computed:            true,
			},
			"sensor_type": schema.StringAttribute{
				MarkdownDescription: "The sensor type for the analytic (read-only).",
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the analytic (read-only).",
				Computed:            true,
			},
			"label": schema.StringAttribute{
				MarkdownDescription: "Display label for the analytic (read-only).",
				Computed:            true,
			},
			"long_description": schema.StringAttribute{
				MarkdownDescription: "Long-form description for the analytic (read-only).",
				Computed:            true,
			},
			"filter": schema.StringAttribute{
				MarkdownDescription: "The filter expression for the analytic (read-only).",
				Computed:            true,
			},
			"level": schema.Int64Attribute{
				MarkdownDescription: "The log level (integer) for the analytic (read-only).",
				Computed:            true,
			},
			"severity": schema.StringAttribute{
				MarkdownDescription: "The base severity of the analytic (read-only — use `tenant_severity` to override).",
				Computed:            true,
			},
			"tags": schema.SetAttribute{
				MarkdownDescription: "Tags for the analytic (read-only).",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"categories": schema.SetAttribute{
				MarkdownDescription: "Categories for the analytic (read-only).",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"snapshot_files": schema.SetAttribute{
				MarkdownDescription: "Snapshot file paths to collect when the analytic triggers (read-only).",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"context_item": schema.SetNestedAttribute{
				MarkdownDescription: "Context enrichment definitions for the analytic (read-only).",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "The context variable name.",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "The context variable type.",
							Computed:            true,
						},
						"expressions": schema.SetAttribute{
							MarkdownDescription: "Expressions to evaluate for this context variable.",
							Computed:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"tenant_actions": schema.SetNestedAttribute{
				MarkdownDescription: "Tenant-level action overrides. Set to override the default actions configured on the Jamf-managed analytic.",
				Optional:            true,
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "The action name (e.g. `Log`, `SmartGroup`, `Webhook`).",
							Required:            true,
						},
						"parameters": schema.MapAttribute{
							MarkdownDescription: "Action parameters as key-value pairs (e.g. `{id = \"smartgroup\"}`).",
							Optional:            true,
							Computed:            true,
							ElementType:         types.StringType,
						},
					},
				},
			},
			"tenant_severity": schema.StringAttribute{
				MarkdownDescription: "Tenant-level severity override. Valid options are: " + common.FormatOptions(severityOptions) + ".",
				Optional:            true,
				Computed:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(severityOptions...),
				},
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
			"jamf": schema.BoolAttribute{
				MarkdownDescription: "Indicates whether the analytic is Jamf-managed. Always `true` for this resource.",
				Computed:            true,
			},
			"remediation": schema.StringAttribute{
				MarkdownDescription: "Remediation guidance associated with the analytic (read-only).",
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

func (r *AnalyticManagedResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

func (r *AnalyticManagedResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *AnalyticManagedResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the Jamf-managed analytic.",
			},
		},
	}
}
