package telemetry

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/validators"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ resource.Resource = &TelemetryV2Resource{}
var _ resource.ResourceWithImportState = &TelemetryV2Resource{}
var _ resource.ResourceWithIdentity = &TelemetryV2Resource{}

// NewTelemetryV2Resource returns a new telemetry v2 resource.
func NewTelemetryV2Resource() resource.Resource {
	return &TelemetryV2Resource{}
}

// TelemetryV2Resource manages a Jamf Protect telemetry v2 configuration.
type TelemetryV2Resource struct {
	service *jamfprotect.Service
}

// Metadata returns the telemetry v2 resource type name.
func (r *TelemetryV2Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_telemetry"
}

// Schema defines the telemetry v2 schema.
func (r *TelemetryV2Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a telemetry v2 configuration in Jamf Protect. Telemetry configurations define which endpoint security events, log files, and performance metrics are collected from managed endpoints.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the telemetry v2 configuration.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the telemetry v2 configuration.",
				Required:            true,
				Validators:          []validator.String{validators.ResourceName()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the telemetry v2 configuration.",
				Optional:            true,
				Computed:            true,
			},
			"log_file_path": schema.SetAttribute{
				MarkdownDescription: "A set of log file paths to collect from endpoints.",
				Required:            true,
				ElementType:         types.StringType,
			},
			"collect_diagnostic_and_crash_reports": schema.BoolAttribute{
				MarkdownDescription: "Whether diagnostic and crash report collection is enabled.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"collect_performance_metrics": schema.BoolAttribute{
				MarkdownDescription: "Whether performance metrics collection is enabled.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"file_hashes": schema.BoolAttribute{
				MarkdownDescription: "Whether file hashing is enabled for telemetry events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_applications_and_processes": schema.BoolAttribute{
				MarkdownDescription: "Collect application and process events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_access_and_authentication": schema.BoolAttribute{
				MarkdownDescription: "Collect access and authentication events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_users_and_groups": schema.BoolAttribute{
				MarkdownDescription: "Collect user and group management events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_persistence": schema.BoolAttribute{
				MarkdownDescription: "Collect persistence-related events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_hardware_and_software": schema.BoolAttribute{
				MarkdownDescription: "Collect hardware and software events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_apple_security": schema.BoolAttribute{
				MarkdownDescription: "Collect Apple security events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"log_system": schema.BoolAttribute{
				MarkdownDescription: "Collect system events.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last update timestamp.",
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

// IdentitySchema defines the telemetry v2 identity schema.
func (r *TelemetryV2Resource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The unique identifier of the telemetry v2 configuration.",
			},
		},
	}
}

// Configure prepares the telemetry service client.
func (r *TelemetryV2Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
}

// ImportState supports importing telemetry configurations by ID.
func (r *TelemetryV2Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
