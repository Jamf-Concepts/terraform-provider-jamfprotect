// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// TestSplitExtendedDataAttributes verifies that UI labels are correctly split into API attrs and related fields.
func TestSplitExtendedDataAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		values       []string
		wantAttrs    []string
		wantRelated  []string
		wantErrCount int
	}{
		{
			name:        "attr only label",
			values:      []string{"Sha1"},
			wantAttrs:   []string{"sha1hex"},
			wantRelated: []string{},
		},
		{
			name:        "related only label",
			values:      []string{"File"},
			wantAttrs:   []string{},
			wantRelated: []string{"file"},
		},
		{
			name:        "mixed attrs and related",
			values:      []string{"Sha256", "Process", "Signing Information", "User"},
			wantAttrs:   []string{"sha256hex", "signingInfo"},
			wantRelated: []string{"process", "user"},
		},
		{
			name:        "empty input",
			values:      []string{},
			wantAttrs:   []string{},
			wantRelated: []string{},
		},
		{
			name:         "unknown label produces error",
			values:       []string{"NotARealAttribute"},
			wantAttrs:    []string{},
			wantRelated:  []string{},
			wantErrCount: 1,
		},
		{
			name:        "all related types",
			values:      []string{"File", "Process", "User", "Group", "Binary"},
			wantAttrs:   []string{},
			wantRelated: []string{"file", "process", "user", "group", "binary"},
		},
		{
			name:        "blocked process maps to process related",
			values:      []string{"Blocked Process", "Blocked Binary"},
			wantAttrs:   []string{},
			wantRelated: []string{"process", "binary"},
		},
		{
			name:        "source and destination process map to process",
			values:      []string{"Source Process", "Destination Process"},
			wantAttrs:   []string{},
			wantRelated: []string{"process", "process"},
		},
		{
			name:        "parent and process group leader map to process",
			values:      []string{"Parent", "Process Group Leader"},
			wantAttrs:   []string{},
			wantRelated: []string{"process", "process"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			gotAttrs, gotRelated := splitExtendedDataAttributes(tt.values, &diags)

			if tt.wantErrCount > 0 {
				if !diags.HasError() {
					t.Fatal("expected diagnostics error")
				}
				if len(diags.Errors()) != tt.wantErrCount {
					t.Errorf("expected %d errors, got %d", tt.wantErrCount, len(diags.Errors()))
				}
				return
			}

			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}
			if !slices.Equal(gotAttrs, tt.wantAttrs) {
				t.Errorf("attrs = %v, want %v", gotAttrs, tt.wantAttrs)
			}
			if !slices.Equal(gotRelated, tt.wantRelated) {
				t.Errorf("related = %v, want %v", gotRelated, tt.wantRelated)
			}
		})
	}
}

// TestMergeExtendedDataAttributes verifies per-event-type label reconstruction from API fields.
func TestMergeExtendedDataAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tfName   string
		attrs    []string
		related  []string
		expected []string
	}{
		{
			name:     "default event type attrs only",
			tfName:   "file_system_event",
			attrs:    []string{"sha1hex", "signingInfo"},
			related:  []string{},
			expected: []string{"Sha1", "Signing Information"},
		},
		{
			name:     "default event type related only",
			tfName:   "file_system_event",
			attrs:    []string{},
			related:  []string{"file", "process", "user", "group"},
			expected: []string{"File", "Process", "User", "Group"},
		},
		{
			name:     "gatekeeper remaps process and binary",
			tfName:   "gatekeeper_event",
			attrs:    []string{},
			related:  []string{"process", "binary"},
			expected: []string{"Blocked Process", "Blocked Binary"},
		},
		{
			name:     "keylog remaps process to source and destination",
			tfName:   "keylog_register_event",
			attrs:    []string{},
			related:  []string{"process", "process"},
			expected: []string{"Source Process", "Destination Process"},
		},
		{
			name:     "process remaps process to parent and pgl",
			tfName:   "process",
			attrs:    []string{"args"},
			related:  []string{"binary", "user", "group", "process", "process"},
			expected: []string{"Args", "Binary", "User", "Group", "Parent", "Process Group Leader"},
		},
		{
			name:     "empty input",
			tfName:   "file",
			attrs:    []string{},
			related:  []string{},
			expected: []string{},
		},
		{
			name:     "deduplication",
			tfName:   "file_system_event",
			attrs:    []string{},
			related:  []string{"file", "file"},
			expected: []string{"File"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics
			got := mergeExtendedDataAttributes(tt.tfName, tt.attrs, tt.related, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags.Errors())
			}
			if !slices.Equal(got, tt.expected) {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestSplitMergeRoundTrip verifies that splitting then merging valid labels for each event type produces the original labels.
func TestSplitMergeRoundTrip(t *testing.T) {
	t.Parallel()

	for tfName, labels := range eventTypeOptions {
		t.Run(tfName, func(t *testing.T) {
			t.Parallel()
			var diags diag.Diagnostics

			attrs, related := splitExtendedDataAttributes(labels, &diags)
			if diags.HasError() {
				t.Fatalf("split error: %v", diags.Errors())
			}

			merged := mergeExtendedDataAttributes(tfName, attrs, related, &diags)
			if diags.HasError() {
				t.Fatalf("merge error: %v", diags.Errors())
			}

			if len(merged) != len(labels) {
				t.Fatalf("roundtrip length mismatch: got %d, want %d\ngot:  %v\nwant: %v", len(merged), len(labels), merged, labels)
			}

			// Compare as sets (order may differ)
			gotSet := map[string]struct{}{}
			for _, v := range merged {
				gotSet[v] = struct{}{}
			}
			for _, want := range labels {
				if _, ok := gotSet[want]; !ok {
					t.Errorf("missing label %q after roundtrip\ngot:  %v\nwant: %v", want, merged, labels)
				}
			}
		})
	}
}

// TestDefaultNonHTTPBatchConfig verifies the default non-HTTP batch configuration.
func TestDefaultNonHTTPBatchConfig(t *testing.T) {
	t.Parallel()

	config := defaultNonHTTPBatchConfig()
	if config["sizeIndex"] != int64(1) {
		t.Errorf("sizeIndex = %v, want 1", config["sizeIndex"])
	}
	if config["windowInSeconds"] != int64(0) {
		t.Errorf("windowInSeconds = %v, want 0", config["windowInSeconds"])
	}
}

// TestSplitSupportedReports verifies report string splitting into alert and log categories.
func TestSplitSupportedReports(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		reports    []string
		wantAlerts []string
		wantLogs   []string
	}{
		{
			name:       "all alert levels",
			reports:    []string{"AlertHigh", "AlertMedium", "AlertLow", "AlertInformational"},
			wantAlerts: []string{"high", "medium", "low", "informational"},
			wantLogs:   []string{},
		},
		{
			name:       "all log types",
			reports:    []string{"Telemetry", "UnifiedLogging"},
			wantAlerts: []string{},
			wantLogs:   []string{"telemetry", "unified_logs"},
		},
		{
			name:       "mixed",
			reports:    []string{"AlertHigh", "Telemetry"},
			wantAlerts: []string{"high"},
			wantLogs:   []string{"telemetry"},
		},
		{
			name:       "empty",
			reports:    []string{},
			wantAlerts: []string{},
			wantLogs:   []string{},
		},
		{
			name:       "unknown report type ignored",
			reports:    []string{"AlertHigh", "SomethingUnknown"},
			wantAlerts: []string{"high"},
			wantLogs:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotAlerts, gotLogs := splitSupportedReports(tt.reports)
			if !slices.Equal(gotAlerts, tt.wantAlerts) {
				t.Errorf("alerts = %v, want %v", gotAlerts, tt.wantAlerts)
			}
			if !slices.Equal(gotLogs, tt.wantLogs) {
				t.Errorf("logs = %v, want %v", gotLogs, tt.wantLogs)
			}
		})
	}
}
