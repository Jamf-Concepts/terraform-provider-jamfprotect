// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package role

// systemRoleNames contains the names of roles that are Jamf-provided built-ins
// (present in every tenant). They can be excluded from list results via the
// list resource's exclude_builtins option.
var systemRoleNames = map[string]struct{}{
	"Full Admin": {},
	"Read Only":  {},
}

// isSystemRoleName returns true when the role is a Jamf-provided built-in.
func isSystemRoleName(name string) bool {
	_, ok := systemRoleNames[name]
	return ok
}
