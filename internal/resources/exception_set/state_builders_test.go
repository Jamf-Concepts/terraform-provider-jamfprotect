// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// TestApplyState_EmptyExceptions verifies that an exception set with no
// exceptions keeps the shape the model already holds: null stays null and an
// explicit empty set stays empty.
func TestApplyState_EmptyExceptions(t *testing.T) {
	t.Parallel()

	exceptionsType := types.ObjectType{AttrTypes: exceptionAttrTypes}
	tests := []struct {
		name       string
		prior      types.Set
		exceptions []jamfprotect.Exception
		wantNull   bool
		wantCount  int
	}{
		{
			name:     "omitted exceptions stay null",
			prior:    types.SetNull(exceptionsType),
			wantNull: true,
		},
		{
			name:  "explicit empty set stays empty",
			prior: types.SetValueMust(exceptionsType, []attr.Value{}),
		},
		{
			name:       "exceptions on the server populate a null attribute",
			prior:      types.SetNull(exceptionsType),
			exceptions: []jamfprotect.Exception{{Type: "TeamId", Value: "ABCDE12345", IgnoreActivity: "Telemetry"}},
			wantCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := ExceptionSetResourceModel{Exceptions: tt.prior}
			var diags diag.Diagnostics
			r := ExceptionSetResource{}
			r.applyState(context.Background(), &data, jamfprotect.ExceptionSet{UUID: "uuid", Name: "test", Exceptions: tt.exceptions}, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if data.Exceptions.IsNull() != tt.wantNull {
				t.Fatalf("exceptions null = %v, want %v", data.Exceptions.IsNull(), tt.wantNull)
			}
			if got := len(data.Exceptions.Elements()); got != tt.wantCount {
				t.Errorf("exceptions has %d elements, want %d", got, tt.wantCount)
			}
		})
	}
}
