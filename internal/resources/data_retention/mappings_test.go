// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package data_retention

import (
	"strings"
	"testing"
)

func TestRetentionDaysOptionsText_ContainsAllValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "30 days", value: "30"},
		{name: "60 days", value: "60"},
		{name: "90 days", value: "90"},
		{name: "180 days", value: "180"},
		{name: "365 days", value: "365"},
	}

	got := retentionDaysOptionsText()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(got, tt.value) {
				t.Errorf("retentionDaysOptionsText() = %q, expected it to contain %q", got, tt.value)
			}
		})
	}
}

func TestRetentionDaysOptionsText_ExactFormat(t *testing.T) {
	t.Parallel()

	expected := "30, 60, 90, 180, 365"
	got := retentionDaysOptionsText()
	if got != expected {
		t.Errorf("retentionDaysOptionsText() = %q, want %q", got, expected)
	}
}
