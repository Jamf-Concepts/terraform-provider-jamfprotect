// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestRuleModelSortKey_Formats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rule     exceptionRuleModel
		expected string
	}{
		{
			name: "AllFieldsPopulated",
			rule: exceptionRuleModel{
				RuleType: types.StringValue("App Signing Info"),
				Value:    types.StringValue("com.example.app"),
				AppID:    types.StringValue("APP123"),
				TeamID:   types.StringValue("TEAM456"),
			},
			expected: "App Signing Info\x1fcom.example.app\x1fAPP123\x1fTEAM456",
		},
		{
			name: "OnlyRuleType",
			rule: exceptionRuleModel{
				RuleType: types.StringValue("Team ID"),
				Value:    types.StringNull(),
				AppID:    types.StringNull(),
				TeamID:   types.StringNull(),
			},
			expected: "Team ID\x1f\x1f\x1f",
		},
		{
			name: "AllNull",
			rule: exceptionRuleModel{
				RuleType: types.StringNull(),
				Value:    types.StringNull(),
				AppID:    types.StringNull(),
				TeamID:   types.StringNull(),
			},
			expected: "\x1f\x1f\x1f",
		},
		{
			name: "AllUnknown",
			rule: exceptionRuleModel{
				RuleType: types.StringUnknown(),
				Value:    types.StringUnknown(),
				AppID:    types.StringUnknown(),
				TeamID:   types.StringUnknown(),
			},
			expected: "\x1f\x1f\x1f",
		},
		{
			name: "RuleTypeAndValue",
			rule: exceptionRuleModel{
				RuleType: types.StringValue("Process Path"),
				Value:    types.StringValue("/usr/bin/example"),
				AppID:    types.StringNull(),
				TeamID:   types.StringNull(),
			},
			expected: "Process Path\x1f/usr/bin/example\x1f\x1f",
		},
		{
			name: "EmptyStrings",
			rule: exceptionRuleModel{
				RuleType: types.StringValue(""),
				Value:    types.StringValue(""),
				AppID:    types.StringValue(""),
				TeamID:   types.StringValue(""),
			},
			expected: "\x1f\x1f\x1f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ruleModelSortKey(tt.rule)
			if result != tt.expected {
				t.Errorf("ruleModelSortKey() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSortRuleModels_Ordering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []exceptionRuleModel
		expected []exceptionRuleModel
	}{
		{
			name:     "EmptySlice",
			input:    []exceptionRuleModel{},
			expected: []exceptionRuleModel{},
		},
		{
			name: "SingleElement",
			input: []exceptionRuleModel{
				{RuleType: types.StringValue("Team ID"), Value: types.StringValue("ABC"), AppID: types.StringNull(), TeamID: types.StringNull()},
			},
			expected: []exceptionRuleModel{
				{RuleType: types.StringValue("Team ID"), Value: types.StringValue("ABC"), AppID: types.StringNull(), TeamID: types.StringNull()},
			},
		},
		{
			name: "SortByRuleType",
			input: []exceptionRuleModel{
				{RuleType: types.StringValue("User"), Value: types.StringValue("admin"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("Process Path"), Value: types.StringValue("/bin/sh"), AppID: types.StringNull(), TeamID: types.StringNull()},
			},
			expected: []exceptionRuleModel{
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("Process Path"), Value: types.StringValue("/bin/sh"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("User"), Value: types.StringValue("admin"), AppID: types.StringNull(), TeamID: types.StringNull()},
			},
		},
		{
			name: "SortByValueWhenRuleTypeSame",
			input: []exceptionRuleModel{
				{RuleType: types.StringValue("Team ID"), Value: types.StringValue("ZZZ"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("Team ID"), Value: types.StringValue("AAA"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("Team ID"), Value: types.StringValue("MMM"), AppID: types.StringNull(), TeamID: types.StringNull()},
			},
			expected: []exceptionRuleModel{
				{RuleType: types.StringValue("Team ID"), Value: types.StringValue("AAA"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("Team ID"), Value: types.StringValue("MMM"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("Team ID"), Value: types.StringValue("ZZZ"), AppID: types.StringNull(), TeamID: types.StringNull()},
			},
		},
		{
			name: "SortByAppIDWhenRuleTypeAndValueSame",
			input: []exceptionRuleModel{
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("B"), TeamID: types.StringNull()},
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("A"), TeamID: types.StringNull()},
			},
			expected: []exceptionRuleModel{
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("A"), TeamID: types.StringNull()},
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("B"), TeamID: types.StringNull()},
			},
		},
		{
			name: "SortByTeamIDWhenAllElseSame",
			input: []exceptionRuleModel{
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("A"), TeamID: types.StringValue("T2")},
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("A"), TeamID: types.StringValue("T1")},
			},
			expected: []exceptionRuleModel{
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("A"), TeamID: types.StringValue("T1")},
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("A"), TeamID: types.StringValue("T2")},
			},
		},
		{
			name: "MixedNullAndPopulatedFields",
			input: []exceptionRuleModel{
				{RuleType: types.StringValue("User"), Value: types.StringValue("admin"), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringNull(), Value: types.StringNull(), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("A1"), TeamID: types.StringValue("T1")},
			},
			expected: []exceptionRuleModel{
				{RuleType: types.StringNull(), Value: types.StringNull(), AppID: types.StringNull(), TeamID: types.StringNull()},
				{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringValue("A1"), TeamID: types.StringValue("T1")},
				{RuleType: types.StringValue("User"), Value: types.StringValue("admin"), AppID: types.StringNull(), TeamID: types.StringNull()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := sortRuleModels(tt.input)

			if len(result) != len(tt.expected) {
				t.Fatalf("sortRuleModels() returned %d elements, want %d", len(result), len(tt.expected))
			}

			for i := range result {
				gotKey := ruleModelSortKey(result[i])
				wantKey := ruleModelSortKey(tt.expected[i])
				if gotKey != wantKey {
					t.Errorf("sortRuleModels()[%d] sort key = %q, want %q", i, gotKey, wantKey)
				}
			}
		})
	}
}

func TestSortRuleModels_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	original := []exceptionRuleModel{
		{RuleType: types.StringValue("User"), Value: types.StringValue("admin"), AppID: types.StringNull(), TeamID: types.StringNull()},
		{RuleType: types.StringValue("App Signing Info"), Value: types.StringValue("com.example"), AppID: types.StringNull(), TeamID: types.StringNull()},
	}

	originalFirstKey := ruleModelSortKey(original[0])
	_ = sortRuleModels(original)
	afterKey := ruleModelSortKey(original[0])

	if originalFirstKey != afterKey {
		t.Error("sortRuleModels() mutated the input slice")
	}
}
