// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package group

import "testing"

// TestIsSystemGroupName verifies built-in group detection.
func TestIsSystemGroupName(t *testing.T) {
	t.Parallel()

	if !isSystemGroupName("Default") {
		t.Error(`expected "Default" to be a system group name`)
	}

	for _, name := range []string{"", "Default ", "default", "My Group"} {
		if isSystemGroupName(name) {
			t.Errorf("expected %q to not be a system group name", name)
		}
	}
}
