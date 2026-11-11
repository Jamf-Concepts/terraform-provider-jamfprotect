// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package custom_prevent_list

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// TestCustomPreventListAPIToDataSourceItem_SortsSets verifies the prevent list sets a
// list belongs to are sorted by name so data source state does not depend on API order.
func TestCustomPreventListAPIToDataSourceItem_SortsSets(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics

	item := customPreventListAPIToDataSourceItem(jamfprotect.CustomPreventList{
		ID:   "221",
		Name: "Trusted teams",
		Type: "TEAMID",
		Sets: []jamfprotect.CustomPreventListSetRef{
			{UUID: "22222222-2222-4222-8222-222222222222", Name: "Zulu"},
			{UUID: "11111111-1111-4111-8111-111111111111", Name: "Alpha"},
		},
	}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	sets := item.Sets.Elements()
	if len(sets) != 2 || !strings.Contains(sets[0].String(), "Alpha") || !strings.Contains(sets[1].String(), "Zulu") {
		t.Errorf("expected sets sorted by name, got %v", sets)
	}
}

// TestCustomPreventListAPIToDataSourceItem_NoSetsIsEmptyList verifies a list that belongs
// to no set maps to a known empty list rather than null.
func TestCustomPreventListAPIToDataSourceItem_NoSetsIsEmptyList(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics

	item := customPreventListAPIToDataSourceItem(jamfprotect.CustomPreventList{ID: "221", Name: "Orphan", Type: "TEAMID"}, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if item.Sets.IsNull() || item.Sets.IsUnknown() || len(item.Sets.Elements()) != 0 {
		t.Errorf("expected a known empty list, got %v", item.Sets)
	}
}
