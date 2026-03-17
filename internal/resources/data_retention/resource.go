// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_retention

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ resource.Resource = &DataRetentionResource{}
var _ resource.ResourceWithImportState = &DataRetentionResource{}
var _ resource.ResourceWithIdentity = &DataRetentionResource{}

// dataRetentionResourceID is the singleton identifier for data retention.
const dataRetentionResourceID = "data_retention_singleton"

// NewDataRetentionResource returns a new data retention resource.
func NewDataRetentionResource() resource.Resource {
	return &DataRetentionResource{}
}

// DataRetentionResource manages data retention settings in Jamf Protect.
type DataRetentionResource struct {
	client *jamfprotect.Client
}

func (r *DataRetentionResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_data_retention"
}

func (r *DataRetentionResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages data retention settings in Jamf Protect. Updates are limited to once every 24 hours.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The singleton identifier for data retention.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"informational_alert_days": schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("Retention days for informational alert data. Allowed values: %s.", retentionDaysOptionsText()),
				Required:            true,
				Validators: []validator.Int64{
					int64validator.OneOf(retentionDaysOptions...),
				},
			},
			"low_medium_high_severity_alert_days": schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("Retention days for low/medium/high severity alerts. Allowed values: %s.", retentionDaysOptionsText()),
				Required:            true,
				Validators: []validator.Int64{
					int64validator.OneOf(retentionDaysOptions...),
				},
			},
			"archived_data_days": schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("Retention days for archived data. Allowed values: %s.", retentionDaysOptionsText()),
				Required:            true,
				Validators: []validator.Int64{
					int64validator.OneOf(retentionDaysOptions...),
				},
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

func (r *DataRetentionResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

// ImportState supports importing data retention by ID.
func (r *DataRetentionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// IdentitySchema defines the identity attributes for data retention.
func (r *DataRetentionResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description:       "The singleton identifier for data retention.",
			},
		},
	}
}
