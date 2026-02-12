// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/graphql"
)

var _ resource.Resource = &PlanResource{}
var _ resource.ResourceWithImportState = &PlanResource{}

func NewPlanResource() resource.Resource {
	return &PlanResource{}
}

// PlanResource manages a Jamf Protect plan.
type PlanResource struct {
	client *graphql.Client
}

// PlanResourceModel maps the resource schema data.
type PlanResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	Hash                 types.String `tfsdk:"hash"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	LogLevel             types.String `tfsdk:"log_level"`
	AutoUpdate           types.Bool   `tfsdk:"auto_update"`
	ActionConfigs        types.String `tfsdk:"action_configs"`
	ExceptionSets        types.List   `tfsdk:"exception_sets"`
	Telemetry            types.String `tfsdk:"telemetry"`
	TelemetryV2          types.String `tfsdk:"telemetry_v2"`
	USBControlSet        types.String `tfsdk:"usb_control_set"`
	AnalyticSets         types.List   `tfsdk:"analytic_sets"`
	CommsConfig          types.Object `tfsdk:"comms_config"`
	InfoSync             types.Object `tfsdk:"info_sync"`
	SignaturesFeedConfig types.Object `tfsdk:"signatures_feed_config"`
	Created              types.String `tfsdk:"created"`
	Updated              types.String `tfsdk:"updated"`
}

// planAnalyticSetModel maps PlanAnalyticSetInput / response.
type planAnalyticSetModel struct {
	Type        types.String `tfsdk:"type"`
	AnalyticSet types.String `tfsdk:"analytic_set"`
}

func (r *PlanResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plan"
}

func (r *PlanResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a plan in Jamf Protect. Plans define the security configuration deployed to endpoints, including analytic sets, action configurations, telemetry settings, and more.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the plan.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"hash": schema.StringAttribute{
				MarkdownDescription: "The configuration hash of the plan.",
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the plan.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the plan.",
				Optional:            true,
				Computed:            true,
			},
			"log_level": schema.StringAttribute{
				MarkdownDescription: "The log level for the plan. Defaults to `ERROR`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("ERROR"),
				Validators: []validator.String{
					stringvalidator.OneOf("DISABLED", "ERROR", "WARNING", "INFO", "DEBUG"),
				},
			},
			"auto_update": schema.BoolAttribute{
				MarkdownDescription: "Whether to enable auto-updates for endpoints using this plan. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"action_configs": schema.StringAttribute{
				MarkdownDescription: "The ID of the action configuration to associate with this plan.",
				Required:            true,
			},
			"exception_sets": schema.ListAttribute{
				MarkdownDescription: "A list of exception set IDs to associate with this plan.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"telemetry": schema.StringAttribute{
				MarkdownDescription: "The ID of the legacy telemetry configuration.",
				Optional:            true,
			},
			"telemetry_v2": schema.StringAttribute{
				MarkdownDescription: "The ID of the v2 telemetry configuration.",
				Optional:            true,
			},
			"usb_control_set": schema.StringAttribute{
				MarkdownDescription: "The ID of the USB control set to associate with this plan.",
				Optional:            true,
			},
			"analytic_sets": schema.ListNestedAttribute{
				MarkdownDescription: "Analytic sets to include in this plan.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "The type of analytic set.",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf("Report", "Prevent"),
							},
						},
						"analytic_set": schema.StringAttribute{
							MarkdownDescription: "The UUID of the analytic set.",
							Required:            true,
						},
					},
				},
			},
			"comms_config": schema.SingleNestedAttribute{
				MarkdownDescription: "Communications configuration for the plan.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"fqdn": schema.StringAttribute{
						MarkdownDescription: "The fully qualified domain name for communications.",
						Required:            true,
					},
					"protocol": schema.StringAttribute{
						MarkdownDescription: "The protocol to use. Defaults to `mqtt`.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("mqtt"),
						Validators: []validator.String{
							stringvalidator.OneOf("mqtt"),
						},
					},
				},
			},
			"info_sync": schema.SingleNestedAttribute{
				MarkdownDescription: "Info sync configuration for the plan.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"attrs": schema.ListAttribute{
						MarkdownDescription: "A list of attribute names to sync.",
						Required:            true,
						ElementType:         types.StringType,
					},
					"insights_sync_interval": schema.Int64Attribute{
						MarkdownDescription: "The interval in seconds for insights data synchronization.",
						Required:            true,
					},
				},
			},
			"signatures_feed_config": schema.SingleNestedAttribute{
				MarkdownDescription: "Signatures feed configuration for the plan.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						MarkdownDescription: "The signatures feed mode. Defaults to `blocking`.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("blocking"),
						Validators: []validator.String{
							stringvalidator.OneOf("blocking", "monitoring", "off"),
						},
					},
				},
			},
			"created": schema.StringAttribute{
				MarkdownDescription: "The creation timestamp.",
				Computed:            true,
			},
			"updated": schema.StringAttribute{
				MarkdownDescription: "The last-updated timestamp.",
				Computed:            true,
			},
		},
	}
}

func (r *PlanResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*graphql.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *graphql.Client, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

// ---------------------------------------------------------------------------
// GraphQL queries — stripped of @skip/@include RBAC directives
// ---------------------------------------------------------------------------

const planFields = `
fragment PlanFields on Plan {
  id
  hash
  name
  description
  created
  updated
  logLevel
  autoUpdate
  commsConfig {
    fqdn
    protocol
  }
  infoSync {
    attrs
    insightsSyncInterval
  }
  signaturesFeedConfig {
    mode
  }
  actionConfigs {
    id
    name
  }
  exceptionSets {
    uuid
    name
    managed
  }
  usbControlSet {
    id
    name
  }
  telemetry {
    id
    name
  }
  telemetryV2 {
    id
    name
  }
  analyticSets {
    type
    analyticSet {
      uuid
      name
      managed
    }
  }
}
`

const createPlanMutation = `
mutation createPlan(
  $name: String!,
  $description: String!,
  $logLevel: LOG_LEVEL_ENUM,
  $actionConfigs: ID!,
  $exceptionSets: [ID!],
  $telemetry: ID,
  $telemetryV2: ID,
  $analyticSets: [PlanAnalyticSetInput!],
  $usbControlSet: ID,
  $commsConfig: CommsConfigInput!,
  $infoSync: InfoSyncInput!,
  $autoUpdate: Boolean!,
  $signaturesFeedConfig: SignaturesFeedConfigInput!
) {
  createPlan(input: {
    name: $name,
    description: $description,
    logLevel: $logLevel,
    actionConfigs: $actionConfigs,
    exceptionSets: $exceptionSets,
    telemetry: $telemetry,
    telemetryV2: $telemetryV2,
    analyticSets: $analyticSets,
    usbControlSet: $usbControlSet,
    commsConfig: $commsConfig,
    infoSync: $infoSync,
    autoUpdate: $autoUpdate,
    signaturesFeedConfig: $signaturesFeedConfig
  }) {
    ...PlanFields
  }
}
` + planFields

const getPlanQuery = `
query getPlan($id: ID!) {
  getPlan(id: $id) {
    ...PlanFields
  }
}
` + planFields

const updatePlanMutation = `
mutation updatePlan(
  $id: ID!,
  $name: String!,
  $description: String!,
  $logLevel: LOG_LEVEL_ENUM,
  $actionConfigs: ID!,
  $exceptionSets: [ID!],
  $telemetry: ID,
  $telemetryV2: ID,
  $analyticSets: [PlanAnalyticSetInput!],
  $usbControlSet: ID,
  $commsConfig: CommsConfigInput!,
  $infoSync: InfoSyncInput!,
  $autoUpdate: Boolean!,
  $signaturesFeedConfig: SignaturesFeedConfigInput!
) {
  updatePlan(id: $id, input: {
    name: $name,
    description: $description,
    logLevel: $logLevel,
    actionConfigs: $actionConfigs,
    exceptionSets: $exceptionSets,
    telemetry: $telemetry,
    telemetryV2: $telemetryV2,
    analyticSets: $analyticSets,
    usbControlSet: $usbControlSet,
    commsConfig: $commsConfig,
    infoSync: $infoSync,
    autoUpdate: $autoUpdate,
    signaturesFeedConfig: $signaturesFeedConfig
  }) {
    ...PlanFields
  }
}
` + planFields

const deletePlanMutation = `
mutation deletePlan($id: ID!) {
  deletePlan(id: $id) {
    id
  }
}
`

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *PlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var result struct {
		CreatePlan planAPIModel `json:"createPlan"`
	}
	if err := r.client.Query(ctx, createPlanMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error creating plan", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.CreatePlan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created plan", map[string]any{"id": data.ID.ValueString()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"id": data.ID.ValueString()}
	var result struct {
		GetPlan *planAPIModel `json:"getPlan"`
	}
	if err := r.client.Query(ctx, getPlanQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error reading plan", err.Error())
		return
	}
	if result.GetPlan == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.apiToState(ctx, &data, *result.GetPlan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state PlanResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = state.ID

	vars := r.buildVariables(ctx, data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	vars["id"] = data.ID.ValueString()

	var result struct {
		UpdatePlan planAPIModel `json:"updatePlan"`
	}
	if err := r.client.Query(ctx, updatePlanMutation, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error updating plan", err.Error())
		return
	}

	r.apiToState(ctx, &data, result.UpdatePlan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PlanResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vars := map[string]any{"id": data.ID.ValueString()}
	if err := r.client.Query(ctx, deletePlanMutation, vars, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting plan", err.Error())
		return
	}

	tflog.Trace(ctx, "deleted plan", map[string]any{"id": data.ID.ValueString()})
}

func (r *PlanResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var data PlanResourceModel
	data.ID = types.StringValue(req.ID)

	vars := map[string]any{"id": req.ID}
	var result struct {
		GetPlan *planAPIModel `json:"getPlan"`
	}
	if err := r.client.Query(ctx, getPlanQuery, vars, &result); err != nil {
		resp.Diagnostics.AddError("Error importing plan", err.Error())
		return
	}
	if result.GetPlan == nil {
		resp.Diagnostics.AddError("Plan not found", fmt.Sprintf("No plan with ID %q", req.ID))
		return
	}

	r.apiToState(ctx, &data, *result.GetPlan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type planAPIModel struct {
	ID                   string                      `json:"id"`
	Hash                 string                      `json:"hash"`
	Name                 string                      `json:"name"`
	Description          string                      `json:"description"`
	Created              string                      `json:"created"`
	Updated              string                      `json:"updated"`
	LogLevel             string                      `json:"logLevel"`
	AutoUpdate           bool                        `json:"autoUpdate"`
	CommsConfig          *planCommsConfigAPIModel    `json:"commsConfig"`
	InfoSync             *planInfoSyncAPIModel       `json:"infoSync"`
	SignaturesFeedConfig *planSignaturesFeedAPIModel `json:"signaturesFeedConfig"`
	ActionConfigs        *planRefAPIModel            `json:"actionConfigs"`
	ExceptionSets        []planExceptionSetAPIModel  `json:"exceptionSets"`
	USBControlSet        *planRefAPIModel            `json:"usbControlSet"`
	Telemetry            *planRefAPIModel            `json:"telemetry"`
	TelemetryV2          *planRefAPIModel            `json:"telemetryV2"`
	AnalyticSets         []planAnalyticSetAPIModel   `json:"analyticSets"`
}

type planCommsConfigAPIModel struct {
	FQDN     string `json:"fqdn"`
	Protocol string `json:"protocol"`
}

type planInfoSyncAPIModel struct {
	Attrs                []string `json:"attrs"`
	InsightsSyncInterval int64    `json:"insightsSyncInterval"`
}

type planSignaturesFeedAPIModel struct {
	Mode string `json:"mode"`
}

type planRefAPIModel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type planExceptionSetAPIModel struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
}

type planAnalyticSetAPIModel struct {
	Type        string                     `json:"type"`
	AnalyticSet planAnalyticSetRefAPIModel `json:"analyticSet"`
}

type planAnalyticSetRefAPIModel struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildVariables converts the Terraform model into GraphQL mutation variables.
func (r *PlanResource) buildVariables(ctx context.Context, data PlanResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":          data.Name.ValueString(),
		"actionConfigs": data.ActionConfigs.ValueString(),
		"autoUpdate":    data.AutoUpdate.ValueBool(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	if !data.LogLevel.IsNull() {
		vars["logLevel"] = data.LogLevel.ValueString()
	}

	if !data.Telemetry.IsNull() {
		vars["telemetry"] = data.Telemetry.ValueString()
	}

	if !data.TelemetryV2.IsNull() {
		vars["telemetryV2"] = data.TelemetryV2.ValueString()
	}

	if !data.USBControlSet.IsNull() {
		vars["usbControlSet"] = data.USBControlSet.ValueString()
	}

	// Exception sets.
	if !data.ExceptionSets.IsNull() {
		vars["exceptionSets"] = listToStrings(ctx, data.ExceptionSets, diags)
	}

	// Analytic sets.
	var analyticSets []map[string]any
	if !data.AnalyticSets.IsNull() {
		var setModels []planAnalyticSetModel
		diags.Append(data.AnalyticSets.ElementsAs(ctx, &setModels, false)...)
		for _, s := range setModels {
			analyticSets = append(analyticSets, map[string]any{
				"type": s.Type.ValueString(),
				"uuid": s.AnalyticSet.ValueString(),
			})
		}
	}
	if analyticSets != nil {
		vars["analyticSets"] = analyticSets
	}

	// Comms config (required).
	commsAttrTypes := map[string]attr.Type{
		"fqdn":     types.StringType,
		"protocol": types.StringType,
	}
	if !data.CommsConfig.IsNull() {
		commsAttrs := data.CommsConfig.Attributes()
		vars["commsConfig"] = map[string]any{
			"fqdn":     commsAttrs["fqdn"].(types.String).ValueString(),
			"protocol": commsAttrs["protocol"].(types.String).ValueString(),
		}
	} else {
		vars["commsConfig"] = map[string]any{
			"fqdn":     "",
			"protocol": "",
		}
	}
	_ = commsAttrTypes

	// Info sync (required).
	if !data.InfoSync.IsNull() {
		infoAttrs := data.InfoSync.Attributes()
		attrsList := infoAttrs["attrs"].(types.List)
		vars["infoSync"] = map[string]any{
			"attrs":                listToStrings(ctx, attrsList, diags),
			"insightsSyncInterval": infoAttrs["insights_sync_interval"].(types.Int64).ValueInt64(),
		}
	} else {
		vars["infoSync"] = map[string]any{
			"attrs":                []string{},
			"insightsSyncInterval": 0,
		}
	}

	// Signatures feed config (required).
	if !data.SignaturesFeedConfig.IsNull() {
		sigAttrs := data.SignaturesFeedConfig.Attributes()
		vars["signaturesFeedConfig"] = map[string]any{
			"mode": sigAttrs["mode"].(types.String).ValueString(),
		}
	} else {
		vars["signaturesFeedConfig"] = map[string]any{
			"mode": "OFF",
		}
	}

	return vars
}

// apiToState maps the API response into the Terraform state model.
func (r *PlanResource) apiToState(_ context.Context, data *PlanResourceModel, api planAPIModel, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Hash = types.StringValue(api.Hash)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.AutoUpdate = types.BoolValue(api.AutoUpdate)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}

	if api.LogLevel != "" {
		data.LogLevel = types.StringValue(api.LogLevel)
	} else {
		data.LogLevel = types.StringNull()
	}

	// Action configs — the API returns an object with id+name; we store just the ID.
	if api.ActionConfigs != nil {
		data.ActionConfigs = types.StringValue(api.ActionConfigs.ID)
	}

	// Exception sets — extract UUIDs.
	if len(api.ExceptionSets) > 0 {
		uuids := make([]string, len(api.ExceptionSets))
		for i, es := range api.ExceptionSets {
			uuids[i] = es.UUID
		}
		data.ExceptionSets = stringsToList(uuids)
	} else {
		data.ExceptionSets = types.ListNull(types.StringType)
	}

	// Telemetry references.
	if api.Telemetry != nil && api.Telemetry.ID != "" {
		data.Telemetry = types.StringValue(api.Telemetry.ID)
	} else {
		data.Telemetry = types.StringNull()
	}

	if api.TelemetryV2 != nil && api.TelemetryV2.ID != "" {
		data.TelemetryV2 = types.StringValue(api.TelemetryV2.ID)
	} else {
		data.TelemetryV2 = types.StringNull()
	}

	// USB control set.
	if api.USBControlSet != nil && api.USBControlSet.ID != "" {
		data.USBControlSet = types.StringValue(api.USBControlSet.ID)
	} else {
		data.USBControlSet = types.StringNull()
	}

	// Analytic sets.
	analyticSetAttrTypes := map[string]attr.Type{
		"type":         types.StringType,
		"analytic_set": types.StringType,
	}
	if len(api.AnalyticSets) > 0 {
		var setVals []attr.Value
		for _, as := range api.AnalyticSets {
			setVals = append(setVals, types.ObjectValueMust(analyticSetAttrTypes, map[string]attr.Value{
				"type":         types.StringValue(as.Type),
				"analytic_set": types.StringValue(as.AnalyticSet.UUID),
			}))
		}
		setList, d := types.ListValue(types.ObjectType{AttrTypes: analyticSetAttrTypes}, setVals)
		diags.Append(d...)
		data.AnalyticSets = setList
	} else {
		data.AnalyticSets = types.ListNull(types.ObjectType{AttrTypes: analyticSetAttrTypes})
	}

	// Comms config.
	commsAttrTypes := map[string]attr.Type{
		"fqdn":     types.StringType,
		"protocol": types.StringType,
	}
	if api.CommsConfig != nil {
		data.CommsConfig = types.ObjectValueMust(commsAttrTypes, map[string]attr.Value{
			"fqdn":     types.StringValue(api.CommsConfig.FQDN),
			"protocol": types.StringValue(api.CommsConfig.Protocol),
		})
	} else {
		data.CommsConfig = types.ObjectNull(commsAttrTypes)
	}

	// Info sync.
	infoSyncAttrTypes := map[string]attr.Type{
		"attrs":                  types.ListType{ElemType: types.StringType},
		"insights_sync_interval": types.Int64Type,
	}
	if api.InfoSync != nil {
		data.InfoSync = types.ObjectValueMust(infoSyncAttrTypes, map[string]attr.Value{
			"attrs":                  stringsToList(api.InfoSync.Attrs),
			"insights_sync_interval": types.Int64Value(api.InfoSync.InsightsSyncInterval),
		})
	} else {
		data.InfoSync = types.ObjectNull(infoSyncAttrTypes)
	}

	// Signatures feed config.
	sigFeedAttrTypes := map[string]attr.Type{
		"mode": types.StringType,
	}
	if api.SignaturesFeedConfig != nil {
		data.SignaturesFeedConfig = types.ObjectValueMust(sigFeedAttrTypes, map[string]attr.Value{
			"mode": types.StringValue(api.SignaturesFeedConfig.Mode),
		})
	} else {
		data.SignaturesFeedConfig = types.ObjectNull(sigFeedAttrTypes)
	}
}
