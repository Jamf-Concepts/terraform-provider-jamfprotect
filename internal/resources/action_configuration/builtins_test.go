// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import "testing"

// TestIsSystemActionConfigName verifies built-in action configuration detection.
func TestIsSystemActionConfigName(t *testing.T) {
	t.Parallel()

	if !isSystemActionConfigName("Default") {
		t.Error(`expected "Default" to be a system action configuration name`)
	}

	for _, name := range []string{"", "Default ", "default", "My Action Config"} {
		if isSystemActionConfigName(name) {
			t.Errorf("expected %q to not be a system action configuration name", name)
		}
	}
}
