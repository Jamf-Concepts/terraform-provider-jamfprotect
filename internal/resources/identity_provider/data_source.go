// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package identity_provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ datasource.DataSource = &IdentityProvidersDataSource{}

// NewIdentityProvidersDataSource returns a new identity providers data source.
func NewIdentityProvidersDataSource() datasource.DataSource {
	return &IdentityProvidersDataSource{}
}

// IdentityProvidersDataSource lists all identity provider connections in Jamf Protect.
type IdentityProvidersDataSource struct {
	client *jamfprotect.Client
}

// IdentityProvidersDataSourceModel maps the data source schema.
type IdentityProvidersDataSourceModel struct {
	IdentityProviders []IdentityProviderDataSourceItemModel `tfsdk:"identity_providers"`
}

// IdentityProviderDataSourceItemModel maps a single identity provider item (read-only).
type IdentityProviderDataSourceItemModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	RequireKnownUsers types.Bool   `tfsdk:"require_known_users"`
	Button            types.String `tfsdk:"button"`
	Created           types.String `tfsdk:"created"`
	Updated           types.String `tfsdk:"updated"`
	Strategy          types.String `tfsdk:"strategy"`
	GroupsSupport     types.Bool   `tfsdk:"groups_support"`
	Source            types.String `tfsdk:"source"`
}

func (d *IdentityProvidersDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity_providers"
}

func (d *IdentityProvidersDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all identity provider connections in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"identity_providers": schema.ListNestedAttribute{
				MarkdownDescription: "The list of identity provider connections.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: identityProviderDataSourceAttributes(),
				},
			},
		},
	}
}

// identityProviderDataSourceAttributes defines the identity provider attributes for data sources.
func identityProviderDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the identity provider connection.",
			Computed:            true,
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name of the identity provider connection.",
			Computed:            true,
		},
		"require_known_users": schema.BoolAttribute{
			MarkdownDescription: "Whether the connection requires known users.",
			Computed:            true,
		},
		"button": schema.StringAttribute{
			MarkdownDescription: "The button style identifier for the connection.",
			Computed:            true,
		},
		"created": schema.StringAttribute{
			MarkdownDescription: "The creation timestamp.",
			Computed:            true,
		},
		"updated": schema.StringAttribute{
			MarkdownDescription: "The last-updated timestamp.",
			Computed:            true,
		},
		"strategy": schema.StringAttribute{
			MarkdownDescription: "The authentication strategy of the connection (e.g. `oidc`, `oidc (public)`).",
			Computed:            true,
		},
		"groups_support": schema.BoolAttribute{
			MarkdownDescription: "Whether the connection supports groups.",
			Computed:            true,
		},
		"source": schema.StringAttribute{
			MarkdownDescription: "The source of the connection.",
			Computed:            true,
		},
	}
}

func (d *IdentityProvidersDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

func (d *IdentityProvidersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data IdentityProvidersDataSourceModel

	items, err := d.client.ListConnections(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing identity providers", err.Error())
		return
	}

	tflog.Trace(ctx, "listed identity providers", map[string]any{"count": len(items)})

	identityProviders := make([]IdentityProviderDataSourceItemModel, 0, len(items))
	for _, api := range items {
		item := connectionAPIToDataSourceItem(api)
		identityProviders = append(identityProviders, item)
	}
	data.IdentityProviders = identityProviders

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
