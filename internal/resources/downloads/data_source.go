// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package downloads

import (
	"context"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// Download package filenames.
const (
	installerPackageName   = "installer.pkg"
	uninstallerPackageName = "uninstaller.pkg"
)

var _ datasource.DataSource = &DownloadsDataSource{}

// NewDownloadsDataSource returns a new downloads data source.
func NewDownloadsDataSource() datasource.DataSource {
	return &DownloadsDataSource{}
}

// DownloadsDataSource retrieves download payloads for Jamf Protect.
type DownloadsDataSource struct {
	service *jamfprotect.Service
	baseURL string
}

// DownloadsDataSourceModel maps the data source schema.
type DownloadsDataSourceModel struct {
	SafelistProfile                    types.String `tfsdk:"safelist_profile"`
	RootCACertificate                  types.String `tfsdk:"root_ca_certificate"`
	CSRCertificate                     types.String `tfsdk:"csr_certificate"`
	WebsocketAuthorizerKey             types.String `tfsdk:"websocket_authorizer_key"`
	NonRemovableSystemExtensionProfile types.String `tfsdk:"non_removable_system_extension_profile"`
	InstallerPackage                   types.Object `tfsdk:"installer_package"`
}

func (d *DownloadsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_downloads"
}

func (d *DownloadsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves Jamf Protect download payloads for installers, profiles, and certificates.",
		Attributes: map[string]schema.Attribute{
			"safelist_profile": schema.StringAttribute{
				MarkdownDescription: "The Jamf Protect Safelist (PPPC) profile payload in base64.",
				Computed:            true,
				Sensitive:           true,
			},
			"root_ca_certificate": schema.StringAttribute{
				MarkdownDescription: "The Root CA certificate payload in base64.",
				Computed:            true,
				Sensitive:           true,
			},
			"csr_certificate": schema.StringAttribute{
				MarkdownDescription: "The CSR certificate payload in base64.",
				Computed:            true,
				Sensitive:           true,
			},
			"websocket_authorizer_key": schema.StringAttribute{
				MarkdownDescription: "The WebSocket Authorizer Key payload in base64.",
				Computed:            true,
				Sensitive:           true,
			},
			"non_removable_system_extension_profile": schema.StringAttribute{
				MarkdownDescription: "The non-removable system extension profile payload in base64.",
				Computed:            true,
				Sensitive:           true,
			},
			"installer_package": schema.SingleNestedAttribute{
				MarkdownDescription: "Installer and uninstaller package metadata.",
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"installer_url": schema.StringAttribute{
						MarkdownDescription: "The Jamf Protect installer package URL.",
						Computed:            true,
						Sensitive:           true,
					},
					"uninstaller_url": schema.StringAttribute{
						MarkdownDescription: "The Jamf Protect uninstaller package URL.",
						Computed:            true,
						Sensitive:           true,
					},
					"version": schema.StringAttribute{
						MarkdownDescription: "The installer package version.",
						Computed:            true,
					},
				},
			},
		},
	}
}

func (d *DownloadsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.service = jamfprotect.ConfigureService(req.ProviderData, &resp.Diagnostics)
	if d.service != nil {
		d.baseURL = d.service.BaseURL()
	}
}

func (d *DownloadsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data DownloadsDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	downloads, err := d.service.GetOrganizationDownloads(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error retrieving downloads", err.Error())
		return
	}
	data.SafelistProfile = stringValueOrNull(downloads.PPPC)
	data.RootCACertificate = stringValueOrNull(downloads.RootCA)
	data.CSRCertificate = stringValueOrNull(downloads.CSR)
	data.WebsocketAuthorizerKey = stringValueOrNull(downloads.WebsocketAuth)
	data.NonRemovableSystemExtensionProfile = stringValueOrNull(downloads.TamperPreventionProfile)
	data.InstallerPackage = buildInstallerPackageObject(d.baseURL, downloads.VanillaPackage, downloads.InstallerUUID)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// stringValueOrNull returns a string value or a null value when empty.
func stringValueOrNull(value string) types.String {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}

// buildPackageURL returns the package URL for the provided base URL and installer UUID.
func buildPackageURL(baseURL, packageName, installerUUID string) string {
	if baseURL == "" || installerUUID == "" {
		return ""
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	u = u.JoinPath(packageName)
	u.RawQuery = installerUUID
	return u.String()
}

// buildInstallerPackageObject maps the installer package into a Terraform object.
func buildInstallerPackageObject(baseURL string, pkg *jamfprotect.VanillaPackage, installerUUID string) types.Object {
	if pkg == nil {
		return types.ObjectNull(installerPackageAttrTypes)
	}
	installerURL := buildPackageURL(baseURL, installerPackageName, installerUUID)
	uninstallerURL := buildPackageURL(baseURL, uninstallerPackageName, installerUUID)
	attrs := map[string]attr.Value{
		"installer_url":   stringValueOrNull(installerURL),
		"uninstaller_url": stringValueOrNull(uninstallerURL),
		"version":         stringValueOrNull(pkg.Version),
	}
	obj, _ := types.ObjectValue(installerPackageAttrTypes, attrs)
	return obj
}
