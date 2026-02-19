// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package role

import "strings"

// isRoleNullTimestampError reports whether the API returned a null timestamp GraphQL error for roles.
func isRoleNullTimestampError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "Cannot return null for non-nullable type") &&
		strings.Contains(message, "Role") &&
		(strings.Contains(message, "getRole.created") || strings.Contains(message, "getRole.updated"))
}
