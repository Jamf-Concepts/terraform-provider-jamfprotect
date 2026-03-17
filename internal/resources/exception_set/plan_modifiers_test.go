// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rsschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// schemaForTest returns the resource schema used to build tfsdk.Plan values.
func schemaForTest() rsschema.Schema {
	r := NewExceptionSetResource()
	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), schemaReq, schemaResp)
	return schemaResp.Schema
}

// tftypesSchemaType returns the tftypes.Type derived from the resource schema.
func tftypesSchemaType(s rsschema.Schema) tftypes.Type {
	return s.Type().TerraformType(context.Background())
}

// buildPlan creates a tfsdk.Plan from a tftypes.Value and the schema.
func buildPlan(t *testing.T, s rsschema.Schema, val tftypes.Value) tfsdk.Plan {
	t.Helper()
	return tfsdk.Plan{
		Schema: s,
		Raw:    val,
	}
}

// ruleObject builds a tftypes.Value representing a single exception rule.
func ruleObject(ruleType, value, appID, teamID *string) tftypes.Value {
	ruleObjType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"rule_type": tftypes.String,
			"value":     tftypes.String,
			"app_id":    tftypes.String,
			"team_id":   tftypes.String,
		},
	}

	vals := map[string]tftypes.Value{
		"rule_type": stringOrNull(ruleType),
		"value":     stringOrNull(value),
		"app_id":    stringOrNull(appID),
		"team_id":   stringOrNull(teamID),
	}

	return tftypes.NewValue(ruleObjType, vals)
}

// exceptionObject builds a tftypes.Value representing a single exception entry.
func exceptionObject(excType, subType *string, rules []tftypes.Value) tftypes.Value {
	ruleObjType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"rule_type": tftypes.String,
			"value":     tftypes.String,
			"app_id":    tftypes.String,
			"team_id":   tftypes.String,
		},
	}
	rulesListType := tftypes.List{ElementType: ruleObjType}
	excObjType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"type":     tftypes.String,
			"sub_type": tftypes.String,
			"rules":    rulesListType,
		},
	}

	vals := map[string]tftypes.Value{
		"type":     stringOrNull(excType),
		"sub_type": stringOrNull(subType),
		"rules":    tftypes.NewValue(rulesListType, rules),
	}

	return tftypes.NewValue(excObjType, vals)
}

// stringOrNull returns a tftypes.String value or a null string.
func stringOrNull(s *string) tftypes.Value {
	if s == nil {
		return tftypes.NewValue(tftypes.String, nil)
	}
	return tftypes.NewValue(tftypes.String, *s)
}

// strPtr returns a pointer to a string literal.
//
//go:fix inline
func strPtr(s string) *string {
	return new(s)
}

// timeoutsNull returns a null tftypes.Value for the timeouts block.
func timeoutsNull() tftypes.Value {
	return tftypes.NewValue(
		tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"create": tftypes.String,
				"read":   tftypes.String,
				"update": tftypes.String,
				"delete": tftypes.String,
			},
		},
		nil,
	)
}

// rootValue builds a complete tftypes.Value for the resource root object.
func rootValue(schemaType tftypes.Type, exceptions tftypes.Value) tftypes.Value {
	return tftypes.NewValue(schemaType, map[string]tftypes.Value{
		"id":          tftypes.NewValue(tftypes.String, nil),
		"name":        tftypes.NewValue(tftypes.String, "test"),
		"description": tftypes.NewValue(tftypes.String, nil),
		"exceptions":  exceptions,
		"created":     tftypes.NewValue(tftypes.String, nil),
		"updated":     tftypes.NewValue(tftypes.String, nil),
		"managed":     tftypes.NewValue(tftypes.Bool, nil),
		"timeouts":    timeoutsNull(),
	})
}

// exceptionsSetType returns the tftypes.Set type for the exceptions attribute.
func exceptionsSetType() tftypes.Set {
	ruleObjType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"rule_type": tftypes.String,
			"value":     tftypes.String,
			"app_id":    tftypes.String,
			"team_id":   tftypes.String,
		},
	}
	return tftypes.Set{
		ElementType: tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"type":     tftypes.String,
				"sub_type": tftypes.String,
				"rules":    tftypes.List{ElementType: ruleObjType},
			},
		},
	}
}

func TestModifyPlan_SortsRules(t *testing.T) {
	t.Parallel()

	s := schemaForTest()
	schemaType := tftypesSchemaType(s)
	setType := exceptionsSetType()

	// Build an exception with unsorted rules: User before Process Path before App Signing Info.
	exc := exceptionObject(
		new("Process Event"),
		nil,
		[]tftypes.Value{
			ruleObject(new("User"), new("admin"), nil, nil),
			ruleObject(new("Process Path"), new("/usr/bin/test"), nil, nil),
			ruleObject(new("App Signing Info"), nil, new("com.example"), new("TEAM1")),
		},
	)

	rawVal := rootValue(schemaType, tftypes.NewValue(setType, []tftypes.Value{exc}))
	plan := buildPlan(t, s, rawVal)

	req := resource.ModifyPlanRequest{
		Plan: plan,
	}
	resp := &resource.ModifyPlanResponse{
		Plan: plan,
	}

	r := &ExceptionSetResource{}
	r.ModifyPlan(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan returned errors: %s", resp.Diagnostics.Errors())
	}

	// Extract the modified plan and verify rule ordering.
	var updatedPlan ExceptionSetResourceModel
	diags := resp.Plan.Get(context.Background(), &updatedPlan)
	if diags.HasError() {
		t.Fatalf("failed to read updated plan: %s", diags.Errors())
	}

	var exceptions []exceptionModel
	diags = updatedPlan.Exceptions.ElementsAs(context.Background(), &exceptions, false)
	if diags.HasError() {
		t.Fatalf("failed to extract exceptions: %s", diags.Errors())
	}

	if len(exceptions) != 1 {
		t.Fatalf("expected 1 exception, got %d", len(exceptions))
	}

	var rules []exceptionRuleModel
	diags = exceptions[0].Rules.ElementsAs(context.Background(), &rules, false)
	if diags.HasError() {
		t.Fatalf("failed to extract rules: %s", diags.Errors())
	}

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}

	// Expected sort order: App Signing Info < Process Path < User (lexicographic by sort key).
	expectedOrder := []string{"App Signing Info", "Process Path", "User"}
	for i, rule := range rules {
		got := rule.RuleType.ValueString()
		if got != expectedOrder[i] {
			t.Errorf("rule[%d].RuleType = %q, want %q", i, got, expectedOrder[i])
		}
	}
}

func TestModifyPlan_NullExceptions(t *testing.T) {
	t.Parallel()

	s := schemaForTest()
	schemaType := tftypesSchemaType(s)
	setType := exceptionsSetType()

	// Build a plan with null exceptions.
	rawVal := rootValue(schemaType, tftypes.NewValue(setType, nil))
	plan := buildPlan(t, s, rawVal)

	req := resource.ModifyPlanRequest{
		Plan: plan,
	}
	resp := &resource.ModifyPlanResponse{
		Plan: plan,
	}

	r := &ExceptionSetResource{}
	r.ModifyPlan(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan returned errors on null exceptions: %s", resp.Diagnostics.Errors())
	}

	// Verify the plan was not modified: exceptions should remain null.
	var updatedPlan ExceptionSetResourceModel
	diags := resp.Plan.Get(context.Background(), &updatedPlan)
	if diags.HasError() {
		t.Fatalf("failed to read updated plan: %s", diags.Errors())
	}

	if !updatedPlan.Exceptions.IsNull() {
		t.Error("expected exceptions to remain null after ModifyPlan")
	}
}

func TestModifyPlan_EmptyExceptions(t *testing.T) {
	t.Parallel()

	s := schemaForTest()
	schemaType := tftypesSchemaType(s)
	setType := exceptionsSetType()

	// Build a plan with an empty exceptions set.
	rawVal := rootValue(schemaType, tftypes.NewValue(setType, []tftypes.Value{}))
	plan := buildPlan(t, s, rawVal)

	req := resource.ModifyPlanRequest{
		Plan: plan,
	}
	resp := &resource.ModifyPlanResponse{
		Plan: plan,
	}

	r := &ExceptionSetResource{}
	r.ModifyPlan(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan returned errors on empty exceptions: %s", resp.Diagnostics.Errors())
	}

	// Verify the plan results in an empty set of exceptions (not null).
	var updatedPlan ExceptionSetResourceModel
	diags := resp.Plan.Get(context.Background(), &updatedPlan)
	if diags.HasError() {
		t.Fatalf("failed to read updated plan: %s", diags.Errors())
	}

	if updatedPlan.Exceptions.IsNull() {
		t.Error("expected exceptions to be empty (not null) after ModifyPlan")
	}

	var exceptions []exceptionModel
	diags = updatedPlan.Exceptions.ElementsAs(context.Background(), &exceptions, false)
	if diags.HasError() {
		t.Fatalf("failed to extract exceptions: %s", diags.Errors())
	}

	if len(exceptions) != 0 {
		t.Errorf("expected 0 exceptions, got %d", len(exceptions))
	}
}
