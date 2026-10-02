// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computeractions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// operationNamePattern extracts the GraphQL operation name from a request query.
var operationNamePattern = regexp.MustCompile(`(?:query|mutation)\s+(\w+)`)

// fakeProtectAPI answers the token endpoint and GraphQL operations from canned
// responses keyed by operation name, and records the operations it served.
type fakeProtectAPI struct {
	mu        sync.Mutex
	responses map[string]string
	calls     []string
}

// newFakeProtectAPI starts a fake Jamf Protect API and returns an SDK client
// pointed at it.
func newFakeProtectAPI(t *testing.T, responses map[string]string) (*fakeProtectAPI, *jamfprotect.Client) {
	t.Helper()

	fake := &fakeProtectAPI{responses: responses}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		name := ""
		if m := operationNamePattern.FindStringSubmatch(body.Query); m != nil {
			name = m[1]
		}
		fake.mu.Lock()
		fake.calls = append(fake.calls, name)
		response, ok := fake.responses[name]
		fake.mu.Unlock()
		if !ok {
			t.Errorf("unexpected operation %q", name)
			response = `{"errors":[{"message":"unexpected operation"}]}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return fake, jamfprotect.NewClient(srv.URL, "test-client-id", "test-secret")
}

// called reports whether the fake served the named operation.
func (f *fakeProtectAPI) called(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Contains(f.calls, name)
}

// invokeSetComputerPlan runs the action against client for one computer and
// plan, without wait_for_checkin, and returns the response.
func invokeSetComputerPlan(t *testing.T, client *jamfprotect.Client, uuid, planID string) *action.InvokeResponse {
	t.Helper()

	ctx := context.Background()
	a := &SetComputerPlanAction{computerAction{client: client}}
	schemaResp := &action.SchemaResponse{}
	a.Schema(ctx, action.SchemaRequest{}, schemaResp)

	raw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"computer_uuids":   tftypes.Set{ElementType: tftypes.String},
			"plan_id":          tftypes.String,
			"wait_for_checkin": tftypes.Bool,
			"timeout":          tftypes.String,
		},
	}, map[string]tftypes.Value{
		"computer_uuids":   tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{tftypes.NewValue(tftypes.String, uuid)}),
		"plan_id":          tftypes.NewValue(tftypes.String, planID),
		"wait_for_checkin": tftypes.NewValue(tftypes.Bool, nil),
		"timeout":          tftypes.NewValue(tftypes.String, nil),
	})

	resp := &action.InvokeResponse{SendProgress: func(action.InvokeProgressEvent) {}}
	a.Invoke(ctx, action.InvokeRequest{Config: tfsdk.Config{Raw: raw, Schema: schemaResp.Schema}}, resp)

	return resp
}

// errorSummaries returns the summary of every error diagnostic in resp.
func errorSummaries(resp *action.InvokeResponse) []string {
	var summaries []string
	for _, d := range resp.Diagnostics.Errors() {
		summaries = append(summaries, d.Summary())
	}

	return summaries
}

// TestSetComputerPlanInvoke_unknownPlan verifies that a plan the tenant does not
// have fails the action before any computer is touched. setComputerPlan accepts
// an unknown numeric plan ID and clears the pending plan, so the pre-check is
// the only thing standing between a typo and a reported success.
func TestSetComputerPlanInvoke_unknownPlan(t *testing.T) {
	t.Parallel()

	fake, client := newFakeProtectAPI(t, map[string]string{
		"getPlan": `{"data":{"getPlan":null},"errors":[{"message":"Plan not found with identifier '999999'","path":["getPlan"]}]}`,
	})

	resp := invokeSetComputerPlan(t, client, uuidA, "999999")

	if got := errorSummaries(resp); !slices.Equal(got, []string{"Plan Not Found"}) {
		t.Fatalf("expected a single Plan Not Found error, got %v", resp.Diagnostics)
	}
	if fake.called("setComputerPlan") {
		t.Error("setComputerPlan was called for a plan that does not exist")
	}
}

// TestSetComputerPlanInvoke_planReadFails verifies that an error reading the
// plan, other than not-found, fails the action without touching any computer.
func TestSetComputerPlanInvoke_planReadFails(t *testing.T) {
	t.Parallel()

	fake, client := newFakeProtectAPI(t, map[string]string{
		"getPlan": `{"data":{"getPlan":null},"errors":[{"message":"id: contains invalid characters","path":["getPlan"]}]}`,
	})

	resp := invokeSetComputerPlan(t, client, uuidA, "abc")

	if got := errorSummaries(resp); !slices.Equal(got, []string{"Set Computer Plan Failed"}) {
		t.Fatalf("expected a single Set Computer Plan Failed error, got %v", resp.Diagnostics)
	}
	if fake.called("setComputerPlan") {
		t.Error("setComputerPlan was called after the plan read failed")
	}
}

// TestSetComputerPlanInvoke_assignmentNotRecorded verifies that a
// setComputerPlan response without the requested plan pending is reported as a
// failure rather than a move.
func TestSetComputerPlanInvoke_assignmentNotRecorded(t *testing.T) {
	t.Parallel()

	_, client := newFakeProtectAPI(t, map[string]string{
		"getPlan":         `{"data":{"getPlan":{"id":"34","name":"Target"}}}`,
		"setComputerPlan": `{"data":{"setComputerPlan":{"uuid":"` + uuidA + `","plan":{"id":"1","name":"Default"},"pendingPlan":null}}}`,
	})

	resp := invokeSetComputerPlan(t, client, uuidA, "34")

	if got := errorSummaries(resp); !slices.Equal(got, []string{"Set Computer Plan Failed"}) {
		t.Fatalf("expected a single Set Computer Plan Failed error, got %v", resp.Diagnostics)
	}
	if detail := resp.Diagnostics.Errors()[0].Detail(); !strings.Contains(detail, "plan 34 was not recorded as pending") {
		t.Errorf("error detail does not explain the failure: %s", detail)
	}
}

// TestSetComputerPlanInvoke_assigned verifies that a recorded pending plan is
// reported as a successful move with no diagnostics.
func TestSetComputerPlanInvoke_assigned(t *testing.T) {
	t.Parallel()

	_, client := newFakeProtectAPI(t, map[string]string{
		"getPlan":         `{"data":{"getPlan":{"id":"34","name":"Target"}}}`,
		"setComputerPlan": `{"data":{"setComputerPlan":{"uuid":"` + uuidA + `","plan":{"id":"1","name":"Default"},"pendingPlan":34}}}`,
	})

	resp := invokeSetComputerPlan(t, client, uuidA, "34")

	if resp.Diagnostics.HasError() || resp.Diagnostics.WarningsCount() > 0 {
		t.Fatalf("expected no diagnostics, got %v", resp.Diagnostics)
	}
}
