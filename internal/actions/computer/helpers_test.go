// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computeractions

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

const (
	uuidA = "11111111-1111-1111-1111-111111111111"
	uuidB = "22222222-2222-2222-2222-222222222222"
)

func stringSet(t *testing.T, values ...string) types.Set {
	t.Helper()

	elements := make([]attr.Value, len(values))
	for i, v := range values {
		elements[i] = types.StringValue(v)
	}
	set, diags := types.SetValue(types.StringType, elements)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building set: %v", diags)
	}

	return set
}

func TestResolveTargets_single(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := resolveTargets(context.Background(), stringSet(t, uuidA), &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(got) != 1 || got[0] != uuidA {
		t.Errorf("expected [%s], got %v", uuidA, got)
	}
}

func TestResolveTargets_bulkSortedAndDeduplicated(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := resolveTargets(context.Background(), stringSet(t, uuidB, uuidA, uuidB), &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	want := []string{uuidA, uuidB}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: expected %s, got %s", i, want[i], got[i])
		}
	}
}

func TestResolveTargets_emptySetIsNoTargets(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := resolveTargets(context.Background(), stringSet(t), &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(got) != 0 {
		t.Errorf("expected no targets, got %v", got)
	}
}

func TestResolveTargets_nullSelectorIsNoTargets(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := resolveTargets(context.Background(), types.SetNull(types.StringType), &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(got) != 0 {
		t.Errorf("expected no targets, got %v", got)
	}
}

func TestPlanSettled(t *testing.T) {
	t.Parallel()

	planID := "34"
	otherPlanID := "35"
	zero := int64(0)
	one := int64(1)

	tests := []struct {
		name     string
		computer *jamfprotect.Computer
		want     bool
	}{
		{
			name:     "on plan with no pending change",
			computer: &jamfprotect.Computer{Plan: &jamfprotect.ComputerPlan{ID: &planID}},
			want:     true,
		},
		{
			name:     "on plan with pending plan zero",
			computer: &jamfprotect.Computer{Plan: &jamfprotect.ComputerPlan{ID: &planID}, PendingPlan: &zero},
			want:     true,
		},
		{
			name:     "on plan with pending plan set",
			computer: &jamfprotect.Computer{Plan: &jamfprotect.ComputerPlan{ID: &planID}, PendingPlan: &one},
			want:     false,
		},
		{
			name:     "on a different plan",
			computer: &jamfprotect.Computer{Plan: &jamfprotect.ComputerPlan{ID: &otherPlanID}},
			want:     false,
		},
		{
			name:     "no plan assigned",
			computer: &jamfprotect.Computer{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := planSettled(tt.computer, planID); got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestComputerLabel(t *testing.T) {
	t.Parallel()

	hostName := "mac-01"
	serial := "C02XXXXXXXXX"
	empty := ""

	tests := []struct {
		name     string
		computer *jamfprotect.Computer
		want     string
	}{
		{name: "nil computer falls back to uuid", computer: nil, want: uuidA},
		{name: "host name and serial", computer: &jamfprotect.Computer{HostName: &hostName, Serial: &serial}, want: uuidA + " (mac-01, C02XXXXXXXXX)"},
		{name: "host name only", computer: &jamfprotect.Computer{HostName: &hostName}, want: uuidA + " (mac-01)"},
		{name: "empty strings fall back to uuid", computer: &jamfprotect.Computer{HostName: &empty, Serial: &empty}, want: uuidA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := computerLabel(uuidA, tt.computer); got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestCheckinStateSummary_reportsObservedSignals(t *testing.T) {
	t.Parallel()

	planID := "34"
	pending := int64(35)
	checkin := "2026-07-28T09:00:00Z"
	computer := &jamfprotect.Computer{
		Plan:        &jamfprotect.ComputerPlan{ID: &planID},
		PendingPlan: &pending,
		Checkin:     &checkin,
	}

	want := uuidA + ": plan=34 pending_plan=35 checkin=2026-07-28T09:00:00Z"
	if got := checkinStateSummary(uuidA, computer); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestCheckinStateSummary_missingSignals(t *testing.T) {
	t.Parallel()

	want := uuidA + ": plan=none pending_plan=null checkin=never"
	if got := checkinStateSummary(uuidA, &jamfprotect.Computer{}); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestPendingSummaries_onlyPendingInDeterministicOrder(t *testing.T) {
	t.Parallel()

	lastSeen := map[string]string{
		uuidB: uuidB + ": pending",
		uuidA: uuidA + ": pending",
	}

	got := pendingSummaries([]string{uuidB, uuidA}, lastSeen)
	want := []string{uuidA + ": pending", uuidB + ": pending"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: expected %q, got %q", i, want[i], got[i])
		}
	}

	settled := pendingSummaries([]string{uuidA}, lastSeen)
	if len(settled) != 1 || settled[0] != uuidA+": pending" {
		t.Errorf("expected only the pending computer, got %v", settled)
	}
}

// TestComputerMissing pins the error strings Jamf Protect actually returns for a
// computer UUID that no longer exists, captured live on 2026-07-28. None of them
// wrap ErrNotFound, so the string matching is the only available signal — if the
// API ever changes these messages, this test is what catches it.
func TestComputerMissing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{
			name: "getComputer non-nullable null",
			err:  errors.New("GetComputer(" + uuidA + "): jamfprotect: graphql error: Cannot return null for non-nullable type: 'ID' within parent 'Computer' (/getComputer/uuid) (path: getComputer.uuid); Cannot return null for non-nullable type: 'String' within parent 'Computer' (/getComputer/certid) (path: getComputer.certid)"),
			want: true,
		},
		{
			name: "deleteComputer non-nullable null",
			err:  errors.New("DeleteComputer(" + uuidA + "): jamfprotect: graphql error: Cannot return null for non-nullable type: 'ID' within parent 'Computer' (/deleteComputer/uuid) (path: deleteComputer.uuid)"),
			want: true,
		},
		{
			name: "setComputerPlan does not exist",
			err:  errors.New("SetComputerPlan(" + uuidA + "): jamfprotect: graphql error: Computer with uuid '" + uuidA + "' does not exist. (path: setComputerPlan) (locations: 3:2)"),
			want: true,
		},
		{
			name: "wrapped ErrNotFound",
			err:  fmt.Errorf("GetComputer(%s): %w", uuidA, jamfprotect.ErrNotFound),
			want: true,
		},
		{
			name: "plan dependency block is not a missing computer",
			err:  errors.New("DeletePlan(465): jamfprotect: graphql error: Action blocked due to dependencies on this resource. (path: deletePlan) (locations: 3:2)"),
			want: false,
		},
		{
			name: "transport failure is not a missing computer",
			err:  errors.New("GetComputer(" + uuidA + "): dial tcp: lookup example.invalid: no such host"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := computerMissing(tt.err); got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestFailureSummary(t *testing.T) {
	t.Parallel()

	want := "  - a: boom\n  - b: bang"
	if got := failureSummary([]string{"a: boom", "b: bang"}); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}
