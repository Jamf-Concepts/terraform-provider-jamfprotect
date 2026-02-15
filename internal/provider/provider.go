// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/action_configuration"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/analytic"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/analytic_set"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/custom_prevent_list"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/exception_set"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/plan"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/removable_storage_control_set"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/telemetry"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/unified_logging_filter"
)

var _ provider.Provider = &JamfProtectProvider{}

// JamfProtectProvider defines the provider implementation.
type JamfProtectProvider struct {
	version string
}

// JamfProtectProviderModel describes the provider data model.
type JamfProtectProviderModel struct {
	URL          types.String `tfsdk:"url"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
}

func (p *JamfProtectProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "jamfprotect"
	resp.Version = p.version
}

func (p *JamfProtectProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Jamf Protect provider allows you to manage Jamf Protect resources such as analytics, prevent lists, plans, and unified logging filters via the Jamf Protect GraphQL API.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				MarkdownDescription: "The base URL of the Jamf Protect instance (e.g. `https://your-tenant.protect.jamfcloud.com`). Can also be set via the `JAMFPROTECT_URL` environment variable.",
				Optional:            true,
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "The API client ID for authentication. Can also be set via the `JAMFPROTECT_CLIENT_ID` environment variable.",
				Optional:            true,
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "The API client secret for authentication. Can also be set via the `JAMFPROTECT_CLIENT_SECRET` environment variable.",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *JamfProtectProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data JamfProtectProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve configuration from provider block or environment variables.
	url := os.Getenv("JAMFPROTECT_URL")
	if !data.URL.IsNull() {
		url = data.URL.ValueString()
	}
	clientID := os.Getenv("JAMFPROTECT_CLIENT_ID")
	if !data.ClientID.IsNull() {
		clientID = data.ClientID.ValueString()
	}
	clientSecret := os.Getenv("JAMFPROTECT_CLIENT_SECRET")
	if !data.ClientSecret.IsNull() {
		clientSecret = data.ClientSecret.ValueString()
	}

	if url == "" {
		resp.Diagnostics.AddError(
			"Missing Jamf Protect URL",
			"The provider requires a Jamf Protect URL. Set the 'url' attribute or the JAMFPROTECT_URL environment variable.",
		)
	}
	if clientID == "" {
		resp.Diagnostics.AddError(
			"Missing Jamf Protect Client ID",
			"The provider requires a client ID. Set the 'client_id' attribute or the JAMFPROTECT_CLIENT_ID environment variable.",
		)
	}
	if clientSecret == "" {
		resp.Diagnostics.AddError(
			"Missing Jamf Protect Client Secret",
			"The provider requires a client secret. Set the 'client_secret' attribute or the JAMFPROTECT_CLIENT_SECRET environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	client := client.NewClientWithVersion(url, clientID, clientSecret, p.version)
	if shouldEnableHTTPLogging() {
		client.SetLogger(NewTerraformLogger())
	}
	if _, err := client.AccessToken(ctx); err != nil {
		resp.Diagnostics.AddError(
			"Jamf Protect authentication failed",
			"The provider could not authenticate with the Jamf Protect API. Verify the URL, client ID, and client secret. Details: "+err.Error(),
		)
		return
	}
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *JamfProtectProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		action_configuration.NewActionConfigResource,
		analytic.NewAnalyticResource,
		analytic_set.NewAnalyticSetResource,
		exception_set.NewExceptionSetResource,
		plan.NewPlanResource,
		custom_prevent_list.NewPreventListResource,
		telemetry.NewTelemetryV2Resource,
		unified_logging_filter.NewUnifiedLoggingFilterResource,
		removable_storage_control_set.NewRemovableStorageControlSetResource,
	}
}

func (p *JamfProtectProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		action_configuration.NewActionConfigsDataSource,
		analytic.NewAnalyticsDataSource,
		analytic_set.NewAnalyticSetsDataSource,
		exception_set.NewExceptionSetsDataSource,
		plan.NewPlansDataSource,
		custom_prevent_list.NewPreventListsDataSource,
		telemetry.NewTelemetriesV2DataSource,
		unified_logging_filter.NewUnifiedLoggingFiltersDataSource,
		removable_storage_control_set.NewRemovableStorageControlSetsDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &JamfProtectProvider{
			version: version,
		}
	}
}

func shouldEnableHTTPLogging() bool {
	level, ok := os.LookupEnv("TF_LOG")
	if !ok {
		return false
	}

	switch strings.ToLower(level) {
	case "debug", "trace":
		return true
	default:
		return false
	}
}
