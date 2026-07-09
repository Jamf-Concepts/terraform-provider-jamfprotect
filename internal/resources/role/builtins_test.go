// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package role

import "testing"

// TestIsSystemRoleName verifies built-in role detection.
func TestIsSystemRoleName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"Full Admin", "Read Only"} {
		if !isSystemRoleName(name) {
			t.Errorf("expected %q to be a system role name", name)
		}
	}

	for _, name := range []string{"", "full admin", "Read Only ", "Admin", "Read"} {
		if isSystemRoleName(name) {
			t.Errorf("expected %q to not be a system role name", name)
		}
	}
}
