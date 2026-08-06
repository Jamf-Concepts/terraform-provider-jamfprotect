// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set

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

	r := &UnifiedLoggingFilterSetResource{}
	var diags diag.Diagnostics

	data := UnifiedLoggingFilterSetResourceModel{
		Name:        types.StringValue("Diagnostics"),
		Description: types.StringValue("Diagnostic filters"),
		Filters: types.SetValueMust(types.StringType, []attr.Value{
			types.StringValue("22222222-2222-4222-8222-222222222222"),
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
	if input.Description != "Diagnostic filters" {
		t.Errorf("expected description %q, got %q", "Diagnostic filters", input.Description)
	}
	if len(input.Filters) != 1 || input.Filters[0] != "22222222-2222-4222-8222-222222222222" {
		t.Errorf("expected one filter UUID, got %v", input.Filters)
	}
}

// TestBuildInput_EmptyFiltersSendsEmptySlice verifies an empty set is sent as an
// empty slice rather than nil, so the API clears membership instead of ignoring
// the field.
func TestBuildInput_EmptyFiltersSendsEmptySlice(t *testing.T) {
	t.Parallel()

	r := &UnifiedLoggingFilterSetResource{}
	var diags diag.Diagnostics

	data := UnifiedLoggingFilterSetResourceModel{
		Name:    types.StringValue("Empty"),
		Filters: types.SetValueMust(types.StringType, []attr.Value{}),
	}

	input := r.buildInput(context.Background(), data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if input == nil {
		t.Fatal("expected non-nil input")
	}
	if input.Filters == nil {
		t.Error("expected a non-nil empty slice so the API clears membership")
	}
	if len(input.Filters) != 0 {
		t.Errorf("expected 0 filters, got %d", len(input.Filters))
	}
}
