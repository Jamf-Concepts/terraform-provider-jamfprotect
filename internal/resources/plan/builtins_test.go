// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import "testing"

// TestIsSystemPlanName verifies built-in plan detection.
func TestIsSystemPlanName(t *testing.T) {
	t.Parallel()

	if !isSystemPlanName("Default") {
		t.Error(`expected "Default" to be a system plan name`)
	}

	for _, name := range []string{"", "Default ", "default", "My Plan", "Defaults"} {
		if isSystemPlanName(name) {
			t.Errorf("expected %q to not be a system plan name", name)
		}
	}
}
