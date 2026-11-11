// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestBuildInput verifies the mutation input carries name, description, and members.
func TestBuildInput(t *testing.T) {
	t.Parallel()

	r := &PreventListSetResource{}
	var diags diag.Diagnostics

	data := PreventListSetResourceModel{
		Name:        types.StringValue("Diagnostics"),
		Description: types.StringValue("Diagnostic lists"),
		PreventLists: types.SetValueMust(types.StringType, []attr.Value{
			types.StringValue("222"),
		}),
	}

	input := r.buildInput(context.Background(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if input == nil {
		t.Fatal("expected non-nil input")
	}
	if input.Name != "Diagnostics" {
		t.Errorf("expected name %q, got %q", "Diagnostics", input.Name)
	}
	if input.Description != "Diagnostic lists" {
		t.Errorf("expected description %q, got %q", "Diagnostic lists", input.Description)
	}
	if len(input.PreventLists) != 1 || input.PreventLists[0] != "222" {
		t.Errorf("expected one prevent list ID, got %v", input.PreventLists)
	}
}

// TestBuildInput_EmptyListsSendsEmptySlice verifies an empty set is sent as an
// empty slice rather than nil, so the API clears membership instead of ignoring
// the field.
func TestBuildInput_EmptyListsSendsEmptySlice(t *testing.T) {
	t.Parallel()

	r := &PreventListSetResource{}
	var diags diag.Diagnostics

	data := PreventListSetResourceModel{
		Name:         types.StringValue("Empty"),
		PreventLists: types.SetValueMust(types.StringType, []attr.Value{}),
	}

	input := r.buildInput(context.Background(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if input == nil {
		t.Fatal("expected non-nil input")
	}
	if input.PreventLists == nil {
		t.Error("expected a non-nil empty slice so the API clears membership")
	}
	if len(input.PreventLists) != 0 {
		t.Errorf("expected 0 prevent lists, got %d", len(input.PreventLists))
	}
}
