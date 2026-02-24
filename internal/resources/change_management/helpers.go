package change_management

import "strings"

// isChangeFreezeNotActiveError reports whether config freeze is already disabled.
func isChangeFreezeNotActiveError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "is not in a change freeze")
}
