// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package group

// systemGroupNames contains the names of groups that are Jamf-provided built-ins
// (present in every tenant). They can be excluded from list results via the
// list resource's exclude_builtins option.
var systemGroupNames = map[string]struct{}{
	"Default": {},
}

// isSystemGroupName returns true when the group is a Jamf-provided built-in.
func isSystemGroupName(name string) bool {
	_, ok := systemGroupNames[name]
	return ok
}
