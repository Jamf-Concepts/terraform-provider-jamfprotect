package data_retention

import (
	"strconv"
	"strings"
)

// retentionDaysOptions enumerates the allowed retention days.
var retentionDaysOptions = []int64{30, 60, 90, 180, 365}

// retentionDaysOptionsText returns a comma-separated string of the allowed retention days for error messages.
func retentionDaysOptionsText() string {
	values := make([]string, len(retentionDaysOptions))
	for i, value := range retentionDaysOptions {
		values[i] = strconv.FormatInt(value, 10)
	}
	return strings.Join(values, ", ")
}
