// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration

// systemActionConfigNames contains the names of action configurations that are
// Jamf-provided built-ins (present in every tenant). They can be excluded from
// list results via the list resource's exclude_builtins option.
var systemActionConfigNames = map[string]struct{}{
	"Default": {},
}

// isSystemActionConfigName returns true when the action configuration is a
// Jamf-provided built-in.
func isSystemActionConfigName(name string) bool {
	_, ok := systemActionConfigNames[name]
	return ok
}
