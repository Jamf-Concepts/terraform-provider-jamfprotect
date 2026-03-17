// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computer

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

var _ datasource.DataSource = &ComputersDataSource{}

// NewComputersDataSource returns a new computers data source.
func NewComputersDataSource() datasource.DataSource {
	return &ComputersDataSource{}
}

// ComputersDataSource lists all computers in Jamf Protect.
type ComputersDataSource struct {
	client *jamfprotect.Client
}

func (d *ComputersDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_computers"
}

func (d *ComputersDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all computers enrolled in Jamf Protect.",
		Attributes: map[string]schema.Attribute{
			"computers": schema.ListNestedAttribute{
				MarkdownDescription: "The list of computers.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: computerDataSourceAttributes(),
				},
			},
		},
	}
}

func (d *ComputersDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = common.ConfigureClient(req.ProviderData, &resp.Diagnostics)
}

func (d *ComputersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state ComputersDataSourceModel

	computers, err := d.client.ListComputers(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Jamf Protect Computers",
			err.Error(),
		)
		return
	}

	// Map response to model
	for _, computer := range computers {
		computerModel := buildComputerModel(computer)
		state.Computers = append(state.Computers, computerModel)
	}

	tflog.Trace(ctx, "listed computers", map[string]any{"count": len(computers)})

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}
