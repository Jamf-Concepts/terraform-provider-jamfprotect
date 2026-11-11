// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package prevent_list_set

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// TestApplyState_PopulatesPreventLists verifies member IDs land in state as a set.
func TestApplyState_PopulatesPreventLists(t *testing.T) {
	t.Parallel()

	r := &PreventListSetResource{}
	var data PreventListSetResourceModel
	var diags diag.Diagnostics

	api := jamfprotect.PreventListSet{
		UUID:        "11111111-1111-4111-8111-111111111111",
		Name:        "Diagnostics",
		Description: "Diagnostic lists",
		Created:     "2026-08-06T00:00:00Z",
		PreventLists: []jamfprotect.PreventListSetList{
			{ID: "222", Name: "Time Machine"},
			{ID: "333", Name: "Screen Sharing"},
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
	if data.Description.ValueString() != "Diagnostic lists" {
		t.Errorf("expected description %q, got %q", "Diagnostic lists", data.Description.ValueString())
	}
	if len(data.PreventLists.Elements()) != 2 {
		t.Fatalf("expected 2 prevent lists in state, got %d", len(data.PreventLists.Elements()))
	}
}

// TestApplyState_EmptyListsIsKnownEmptySet verifies an empty membership becomes a
// known empty set rather than null. A null here would not match a `prevent_lists = []`
// configuration and Terraform would report an inconsistent result after apply.
func TestApplyState_EmptyListsIsKnownEmptySet(t *testing.T) {
	t.Parallel()

	r := &PreventListSetResource{}
	var data PreventListSetResourceModel
	var diags diag.Diagnostics

	r.applyState(context.Background(), &data, jamfprotect.PreventListSet{
		UUID: "11111111-1111-4111-8111-111111111111",
		Name: "Empty",
	}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if data.PreventLists.IsNull() {
		t.Error("expected prevent_lists to be a known empty set, got null")
	}
	if data.PreventLists.IsUnknown() {
		t.Error("expected prevent_lists to be a known empty set, got unknown")
	}
	if len(data.PreventLists.Elements()) != 0 {
		t.Errorf("expected 0 prevent lists, got %d", len(data.PreventLists.Elements()))
	}
}

// TestPreventListSetAPIToDataSourceItem verifies prevent lists and plans map into lists.
func TestPreventListSetAPIToDataSourceItem(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics

	item := preventListSetAPIToDataSourceItem(jamfprotect.PreventListSet{
		UUID:        "11111111-1111-4111-8111-111111111111",
		Name:        "Diagnostics",
		Description: "Diagnostic lists",
		Created:     "2026-08-06T00:00:00Z",
		Updated:     "2026-08-07T00:00:00Z",
		PreventLists: []jamfprotect.PreventListSetList{
			{ID: "222", Name: "Time Machine"},
		},
		Plans: []jamfprotect.PreventListSetPlan{
			{ID: "464", Name: "Default2"},
		},
	}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(item.PreventLists.Elements()) != 1 {
		t.Errorf("expected 1 prevent list, got %d", len(item.PreventLists.Elements()))
	}
	if len(item.Plans.Elements()) != 1 {
		t.Errorf("expected 1 plan, got %d", len(item.Plans.Elements()))
	}
	if item.Updated.ValueString() != "2026-08-07T00:00:00Z" {
		t.Errorf("expected updated timestamp, got %q", item.Updated.ValueString())
	}
}

// TestPreventListSetAPIToDataSourceItem_EmptyDescriptionIsNull verifies an absent
// description becomes null rather than an empty string in data source state.
func TestPreventListSetAPIToDataSourceItem_EmptyDescriptionIsNull(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics

	item := preventListSetAPIToDataSourceItem(jamfprotect.PreventListSet{
		UUID: "11111111-1111-4111-8111-111111111111",
		Name: "No description",
	}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !item.Description.IsNull() {
		t.Errorf("expected null description, got %q", item.Description.ValueString())
	}
	if item.PreventLists.IsNull() || item.Plans.IsNull() {
		t.Error("expected empty lists for prevent lists and plans, got null")
	}
}

// TestPreventListSetAPIToDataSourceItem_SortsNestedLists verifies nested prevent lists
// and plans are sorted by name so data source state does not depend on API order.
func TestPreventListSetAPIToDataSourceItem_SortsNestedLists(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics

	item := preventListSetAPIToDataSourceItem(jamfprotect.PreventListSet{
		UUID: "11111111-1111-4111-8111-111111111111",
		Name: "Unsorted",
		PreventLists: []jamfprotect.PreventListSetList{
			{ID: "3", Name: "Zulu"},
			{ID: "1", Name: "Alpha"},
		},
		Plans: []jamfprotect.PreventListSetPlan{
			{ID: "9", Name: "Second"},
			{ID: "8", Name: "First"},
		},
	}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	lists := item.PreventLists.Elements()
	if len(lists) != 2 || !strings.Contains(lists[0].String(), "Alpha") || !strings.Contains(lists[1].String(), "Zulu") {
		t.Errorf("expected prevent lists sorted by name, got %v", lists)
	}
	plans := item.Plans.Elements()
	if len(plans) != 2 || !strings.Contains(plans[0].String(), "First") || !strings.Contains(plans[1].String(), "Second") {
		t.Errorf("expected plans sorted by name, got %v", plans)
	}
}
