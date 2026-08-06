// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter_set

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// TestApplyState_PopulatesFilters verifies member UUIDs land in state as a set.
func TestApplyState_PopulatesFilters(t *testing.T) {
	t.Parallel()

	r := &UnifiedLoggingFilterSetResource{}
	var data UnifiedLoggingFilterSetResourceModel
	var diags diag.Diagnostics

	api := jamfprotect.UnifiedLoggingFilterSet{
		UUID:        "11111111-1111-4111-8111-111111111111",
		Name:        "Diagnostics",
		Description: "Diagnostic filters",
		Created:     "2026-08-06T00:00:00Z",
		Filters: []jamfprotect.UnifiedLoggingFilterSetFilter{
			{UUID: "22222222-2222-4222-8222-222222222222", Name: "Time Machine"},
			{UUID: "33333333-3333-4333-8333-333333333333", Name: "Screen Sharing"},
		},
	}

	r.applyState(context.Background(), &data, api, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if data.ID.ValueString() != api.UUID {
		t.Errorf("expected ID %q, got %q", api.UUID, data.ID.ValueString())
	}
	if data.Name.ValueString() != "Diagnostics" {
		t.Errorf("expected name %q, got %q", "Diagnostics", data.Name.ValueString())
	}
	if data.Description.ValueString() != "Diagnostic filters" {
		t.Errorf("expected description %q, got %q", "Diagnostic filters", data.Description.ValueString())
	}
	if len(data.Filters.Elements()) != 2 {
		t.Fatalf("expected 2 filters in state, got %d", len(data.Filters.Elements()))
	}
}

// TestApplyState_EmptyFiltersIsKnownEmptySet verifies an empty membership becomes a
// known empty set rather than null. A null here would not match a `filters = []`
// configuration and Terraform would report an inconsistent result after apply.
func TestApplyState_EmptyFiltersIsKnownEmptySet(t *testing.T) {
	t.Parallel()

	r := &UnifiedLoggingFilterSetResource{}
	var data UnifiedLoggingFilterSetResourceModel
	var diags diag.Diagnostics

	r.applyState(context.Background(), &data, jamfprotect.UnifiedLoggingFilterSet{
		UUID: "11111111-1111-4111-8111-111111111111",
		Name: "Empty",
	}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if data.Filters.IsNull() {
		t.Error("expected filters to be a known empty set, got null")
	}
	if data.Filters.IsUnknown() {
		t.Error("expected filters to be a known empty set, got unknown")
	}
	if len(data.Filters.Elements()) != 0 {
		t.Errorf("expected 0 filters, got %d", len(data.Filters.Elements()))
	}
}

// TestFilterSetAPIToDataSourceItem verifies filters and plans map into lists.
func TestFilterSetAPIToDataSourceItem(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics

	item := filterSetAPIToDataSourceItem(jamfprotect.UnifiedLoggingFilterSet{
		UUID:        "11111111-1111-4111-8111-111111111111",
		Name:        "Diagnostics",
		Description: "Diagnostic filters",
		Created:     "2026-08-06T00:00:00Z",
		Updated:     "2026-08-07T00:00:00Z",
		Filters: []jamfprotect.UnifiedLoggingFilterSetFilter{
			{UUID: "22222222-2222-4222-8222-222222222222", Name: "Time Machine"},
		},
		Plans: []jamfprotect.UnifiedLoggingFilterSetPlan{
			{ID: "464", Name: "Default2"},
		},
	}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(item.Filters.Elements()) != 1 {
		t.Errorf("expected 1 filter, got %d", len(item.Filters.Elements()))
	}
	if len(item.Plans.Elements()) != 1 {
		t.Errorf("expected 1 plan, got %d", len(item.Plans.Elements()))
	}
	if item.Updated.ValueString() != "2026-08-07T00:00:00Z" {
		t.Errorf("expected updated timestamp, got %q", item.Updated.ValueString())
	}
}

// TestFilterSetAPIToDataSourceItem_EmptyDescriptionIsNull verifies an absent
// description becomes null rather than an empty string in data source state.
func TestFilterSetAPIToDataSourceItem_EmptyDescriptionIsNull(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics

	item := filterSetAPIToDataSourceItem(jamfprotect.UnifiedLoggingFilterSet{
		UUID: "11111111-1111-4111-8111-111111111111",
		Name: "No description",
	}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !item.Description.IsNull() {
		t.Errorf("expected null description, got %q", item.Description.ValueString())
	}
	if item.Filters.IsNull() || item.Plans.IsNull() {
		t.Error("expected empty lists for filters and plans, got null")
	}
}
