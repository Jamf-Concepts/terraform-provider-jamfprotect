// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &PlanConfigurationProfileDataSource{}

// NewPlanConfigurationProfileDataSource returns a new plan configuration profile data source.
func NewPlanConfigurationProfileDataSource() datasource.DataSource {
	return &PlanConfigurationProfileDataSource{}
}

// PlanConfigurationProfileDataSource retrieves a plan configuration profile payload.
type PlanConfigurationProfileDataSource struct {
	service *jamfprotect.Service
}

// PlanConfigurationProfileDataSourceModel maps the data source schema.
type PlanConfigurationProfileDataSourceModel struct {
	ID                            types.String `tfsdk:"id"`
	SignProfile                   types.Bool   `tfsdk:"sign_profile"`
	IncludePPPCPayload            types.Bool   `tfsdk:"include_pppc_payload"`
	IncludeSystemExtensionPayload types.Bool   `tfsdk:"include_system_extension_payload"`
	IncludeLoginBackgroundItems   types.Bool   `tfsdk:"include_login_background_items_payload"`
	IncludeWebsocketAuthorizerKey types.Bool   `tfsdk:"include_websocket_authorizer_key"`
	IncludeRootCACertificate      types.Bool   `tfsdk:"include_root_ca_certificate"`
	IncludeCSRCertificate         types.Bool   `tfsdk:"include_csr_certificate"`
	IncludeBootstrapToken         types.Bool   `tfsdk:"include_bootstrap_token"`
	Profile                       types.String `tfsdk:"profile"`
}

func (d *PlanConfigurationProfileDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plan_configuration_profile"
}

func (d *PlanConfigurationProfileDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a configuration profile payload for a plan. Note that Jamf Protect generates a new configuration profile each time this endpoint is called, so the profile will differ on each read. Use a `lifecycle` block with `ignore_changes` to prevent unnecessary updates to resources that consume this data source.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the plan.",
				Required:            true,
			},
			"sign_profile": schema.BoolAttribute{
				MarkdownDescription: "Whether to sign the configuration profile payload.",
				Optional:            true,
			},
			"include_pppc_payload": schema.BoolAttribute{
				MarkdownDescription: "Whether to include the PPPC payload.",
				Optional:            true,
			},
			"include_system_extension_payload": schema.BoolAttribute{
				MarkdownDescription: "Whether to include the System Extension payload.",
				Optional:            true,
			},
			"include_login_background_items_payload": schema.BoolAttribute{
				MarkdownDescription: "Whether to include the Login & Background Items payload.",
				Optional:            true,
			},
			"include_websocket_authorizer_key": schema.BoolAttribute{
				MarkdownDescription: "Whether to include the Websocket Authorizer Key.",
				Optional:            true,
			},
			"include_root_ca_certificate": schema.BoolAttribute{
				MarkdownDescription: "Whether to include the Root CA certificate.",
				Optional:            true,
			},
			"include_csr_certificate": schema.BoolAttribute{
				MarkdownDescription: "Whether to include the CSR certificate.",
				Optional:            true,
			},
			"include_bootstrap_token": schema.BoolAttribute{
				MarkdownDescription: "Whether to include the Bootstrap Token payload.",
				Optional:            true,
			},
			"profile": schema.StringAttribute{
				MarkdownDescription: "The configuration profile payload (base64-encoded).",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (d *PlanConfigurationProfileDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}
	d.service = jamfprotect.NewService(client)
}

func (d *PlanConfigurationProfileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PlanConfigurationProfileDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.ID.IsNull() || data.ID.IsUnknown() {
		resp.Diagnostics.AddError("Missing plan ID", "The plan ID is required to retrieve a configuration profile.")
		return
	}

	signProfile := boolValueOrDefault(data.SignProfile, true)
	includePPPC := boolValueOrDefault(data.IncludePPPCPayload, true)
	includeSystemExtension := boolValueOrDefault(data.IncludeSystemExtensionPayload, true)
	includeLoginBackgroundItems := boolValueOrDefault(data.IncludeLoginBackgroundItems, true)
	includeWebsocketAuthorizerKey := boolValueOrDefault(data.IncludeWebsocketAuthorizerKey, true)
	includeRootCACertificate := boolValueOrDefault(data.IncludeRootCACertificate, true)
	includeCSRCertificate := boolValueOrDefault(data.IncludeCSRCertificate, true)
	includeBootstrapToken := boolValueOrDefault(data.IncludeBootstrapToken, true)

	input := jamfprotect.PlanConfigProfileOptionsInput{
		TokenOptions: jamfprotect.PlanConfigProfileTokenOptionsInput{
			XPC:              false,
			KeychainClientID: false,
		},
		Sign:              signProfile,
		PPPC:              includePPPC,
		Token:             includeBootstrapToken,
		CA:                includeRootCACertificate,
		CSR:               includeCSRCertificate,
		Websocket:         includeWebsocketAuthorizerKey,
		SystemExtension:   includeSystemExtension,
		ServiceManagement: includeLoginBackgroundItems,
	}

	profile, err := d.service.GetPlansConfigProfile(ctx, data.ID.ValueString(), &input)
	if err != nil {
		resp.Diagnostics.AddError("Error retrieving plan configuration profile", err.Error())
		return
	}

	data.SignProfile = types.BoolValue(signProfile)
	data.IncludePPPCPayload = types.BoolValue(includePPPC)
	data.IncludeSystemExtensionPayload = types.BoolValue(includeSystemExtension)
	data.IncludeLoginBackgroundItems = types.BoolValue(includeLoginBackgroundItems)
	data.IncludeWebsocketAuthorizerKey = types.BoolValue(includeWebsocketAuthorizerKey)
	data.IncludeRootCACertificate = types.BoolValue(includeRootCACertificate)
	data.IncludeCSRCertificate = types.BoolValue(includeCSRCertificate)
	data.IncludeBootstrapToken = types.BoolValue(includeBootstrapToken)
	data.Profile = types.StringValue(profile)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// boolValueOrDefault resolves a Terraform bool with a fallback value.
func boolValueOrDefault(value types.Bool, defaultValue bool) bool {
	if value.IsNull() || value.IsUnknown() {
		return defaultValue
	}
	return value.ValueBool()
}
