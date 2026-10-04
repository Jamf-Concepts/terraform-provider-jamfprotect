// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// analyticActionsModifierRequest builds a plan modifier request whose plan carries the given
// Smart Group attributes, prior analytic_actions and planned analytic_actions.
func analyticActionsModifierRequest(t *testing.T, add types.Bool, identifier types.String, prior, planned types.List) planmodifier.ListRequest {
	t.Helper()
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	(&AnalyticResource{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}
	values := map[string]any{
		"add_to_jamf_pro_smart_group":     add,
		"jamf_pro_smart_group_identifier": identifier,
		"analytic_actions":                planned,
	}
	for name, value := range values {
		if d := plan.SetAttribute(ctx, path.Root(name), value); d.HasError() {
			t.Fatalf("plan.SetAttribute(%s): %s", name, d.Errors()[0].Detail())
		}
	}
	return planmodifier.ListRequest{
		Plan:       plan,
		StateValue: prior,
		PlanValue:  planned,
	}
}

func TestAnalyticActionsPlanModifier_ComputesWhenUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	unknown := types.ListUnknown(types.ObjectType{AttrTypes: analyticActionAttrTypes})
	req := analyticActionsModifierRequest(t, types.BoolValue(true), types.StringValue("new-group"), consolePriorActions(t), unknown)
	resp := planmodifier.ListResponse{PlanValue: req.PlanValue}

	analyticActionsPlanModifier{}.PlanModifyList(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %s", resp.Diagnostics.Errors()[0].Detail())
	}
	if resp.PlanValue.IsUnknown() {
		t.Fatal("expected a known planned value")
	}

	var actions []analyticActionModel
	if d := resp.PlanValue.ElementsAs(ctx, &actions, false); d.HasError() {
		t.Fatalf("ElementsAs: %s", d.Errors()[0].Detail())
	}
	want := []string{"Report", "SmartGroup id=new-group", "Webhook url=https://example.invalid/hook retries=3"}
	if got := actionSummary(t, actions); !equalStrings(got, want) {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestAnalyticActionsPlanModifier_KeepsKnownPlan(t *testing.T) {
	t.Parallel()

	prior := consolePriorActions(t)
	req := analyticActionsModifierRequest(t, types.BoolValue(false), types.StringNull(), prior, prior)
	resp := planmodifier.ListResponse{PlanValue: req.PlanValue}

	analyticActionsPlanModifier{}.PlanModifyList(context.Background(), req, &resp)
	if !resp.PlanValue.Equal(prior) {
		t.Errorf("expected the known planned value to be left unchanged, got %v", resp.PlanValue)
	}
}

func TestAnalyticActionsPlanModifier_LeavesUnknownWhenSmartGroupUnknown(t *testing.T) {
	t.Parallel()

	unknown := types.ListUnknown(types.ObjectType{AttrTypes: analyticActionAttrTypes})
	req := analyticActionsModifierRequest(t, types.BoolValue(true), types.StringUnknown(), consolePriorActions(t), unknown)
	resp := planmodifier.ListResponse{PlanValue: req.PlanValue}

	analyticActionsPlanModifier{}.PlanModifyList(context.Background(), req, &resp)
	if !resp.PlanValue.IsUnknown() {
		t.Errorf("expected analytic_actions to stay unknown, got %v", resp.PlanValue)
	}
}

func TestAnalyticActionsPlanModifier_LeavesUnknownWhenStateNull(t *testing.T) {
	t.Parallel()

	elemType := types.ObjectType{AttrTypes: analyticActionAttrTypes}
	unknown := types.ListUnknown(elemType)
	req := analyticActionsModifierRequest(t, types.BoolValue(true), types.StringValue("new-group"), types.ListNull(elemType), unknown)
	resp := planmodifier.ListResponse{PlanValue: req.PlanValue}

	analyticActionsPlanModifier{}.PlanModifyList(context.Background(), req, &resp)
	if !resp.PlanValue.IsUnknown() {
		t.Errorf("expected analytic_actions to stay unknown when prior state holds null, got %v", resp.PlanValue)
	}
}
