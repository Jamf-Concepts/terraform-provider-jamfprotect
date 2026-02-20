package computer

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

var _ datasource.DataSource = &ComputerDataSource{}

// NewComputerDataSource returns a new computer data source.
func NewComputerDataSource() datasource.DataSource {
	return &ComputerDataSource{}
}

// ComputerDataSource retrieves a single computer by UUID.
type ComputerDataSource struct {
	service *jamfprotect.Service
}

func (d *ComputerDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_computer"
}

func (d *ComputerDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := computerDataSourceAttributes()
	// Override UUID to be required input instead of computed
	attrs["uuid"] = schema.StringAttribute{
		MarkdownDescription: "The unique identifier of the computer to retrieve.",
		Required:            true,
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a single computer from Jamf Protect by UUID.",
		Attributes:          attrs,
	}
}

func (d *ComputerDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.service = jamfprotect.NewService(client)
}

func (d *ComputerDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config ComputerModel

	// Read configuration
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get computer from API
	uuid := config.UUID.ValueString()
	computer, err := d.service.GetComputer(ctx, uuid)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Jamf Protect Computer",
			err.Error(),
		)
		return
	}

	if computer == nil {
		resp.Diagnostics.AddError(
			"Computer Not Found",
			fmt.Sprintf("No computer found with UUID: %s", uuid),
		)
		return
	}

	// Map response to state
	state := buildComputerModel(*computer)
	// Preserve the UUID from the config
	state.UUID = types.StringValue(uuid)

	tflog.Trace(ctx, "read computer", map[string]any{"uuid": uuid})

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}
