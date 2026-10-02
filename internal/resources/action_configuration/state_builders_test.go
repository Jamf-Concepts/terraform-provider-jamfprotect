// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"
	"testing"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// testSecret is the value_wo secret the API returns, which must never reach state.
const testSecret = "Bearer SECRET"

// plainHeader returns a prior header model that stores its value in state.
func plainHeader(name, value string) endpointHeaderModel {
	return endpointHeaderModel{Header: types.StringValue(name), Value: types.StringValue(value), ValueWO: types.StringNull(), ValueWOVersion: types.StringNull()}
}

// writeOnlyHeader returns a prior header model managed through value_wo.
func writeOnlyHeader(name, version string) endpointHeaderModel {
	return endpointHeaderModel{Header: types.StringValue(name), Value: types.StringNull(), ValueWO: types.StringNull(), ValueWOVersion: types.StringValue(version)}
}

// httpClient returns an API HTTP report client carrying the given headers.
func httpClient(headers ...jamfprotect.ReportClientHeader) jamfprotect.ReportClient {
	return jamfprotect.ReportClient{Type: "Http", Params: jamfprotect.ReportClientParams{URL: "https://example.invalid/hook", Method: "POST", Headers: headers}}
}

// stateHeaders flattens HTTP endpoint state into header models per endpoint.
func stateHeaders(t *testing.T, list types.List) [][]endpointHeaderModel {
	t.Helper()
	ctx := context.Background()
	var endpoints []httpEndpointBlockModel
	if d := list.ElementsAs(ctx, &endpoints, false); d.HasError() {
		t.Fatalf("endpoints: %v", d)
	}
	out := make([][]endpointHeaderModel, 0, len(endpoints))
	for _, endpoint := range endpoints {
		var headers []endpointHeaderModel
		if !endpoint.Headers.IsNull() {
			if d := endpoint.Headers.ElementsAs(ctx, &headers, false); d.HasError() {
				t.Fatalf("headers: %v", d)
			}
		}
		out = append(out, headers)
	}
	return out
}

// TestBuildHTTPEndpointsState_HeaderValues verifies, across three consecutive refreshes each fed
// the previous refresh's state, that a value_wo secret never reaches state whatever changed outside
// Terraform, and that an unchanged configuration keeps its plain values and converges.
func TestBuildHTTPEndpointsState_HeaderValues(t *testing.T) {
	t.Parallel()

	auth := func(value string) jamfprotect.ReportClientHeader {
		return jamfprotect.ReportClientHeader{Header: "Authorization", Value: value}
	}
	contentType := jamfprotect.ReportClientHeader{Header: "Content-Type", Value: "application/json"}
	null := types.StringNull()
	str := types.StringValue

	tests := []struct {
		name        string
		prior       map[headerPosition]endpointHeaderModel
		clients     []jamfprotect.ReportClient
		wantValues  [][]types.String
		wantVersion [][]types.String
	}{
		{
			name: "unchanged configuration",
			prior: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 0}: plainHeader("Content-Type", "application/json"),
				{endpoint: 0, header: 1}: writeOnlyHeader("Authorization", "1"),
			},
			clients:     []jamfprotect.ReportClient{httpClient(contentType, auth(testSecret))},
			wantValues:  [][]types.String{{str("application/json"), null}},
			wantVersion: [][]types.String{{null, str("1")}},
		},
		{
			name: "write-only and same-named plain header on different endpoints",
			prior: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 0}: writeOnlyHeader("Authorization", "1"),
				{endpoint: 1, header: 0}: plainHeader("Authorization", "Bearer PLAIN"),
			},
			clients:     []jamfprotect.ReportClient{httpClient(auth(testSecret)), httpClient(auth("Bearer PLAIN"))},
			wantValues:  [][]types.String{{null}, {str("Bearer PLAIN")}},
			wantVersion: [][]types.String{{str("1")}, {null}},
		},
		{
			name: "header moved within its endpoint",
			prior: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 0}: plainHeader("Content-Type", "application/json"),
				{endpoint: 0, header: 1}: writeOnlyHeader("Authorization", "1"),
			},
			clients:     []jamfprotect.ReportClient{httpClient(auth(testSecret))},
			wantValues:  [][]types.String{{null}},
			wantVersion: [][]types.String{{str("1")}},
		},
		{
			name: "earlier endpoint deleted",
			prior: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 0}: plainHeader("Content-Type", "application/json"),
				{endpoint: 1, header: 0}: writeOnlyHeader("Authorization", "1"),
			},
			clients:     []jamfprotect.ReportClient{httpClient(auth(testSecret))},
			wantValues:  [][]types.String{{null}},
			wantVersion: [][]types.String{{null}},
		},
		{
			name:        "header renamed on the server",
			prior:       map[headerPosition]endpointHeaderModel{{endpoint: 0, header: 0}: writeOnlyHeader("Authorization", "1")},
			clients:     []jamfprotect.ReportClient{httpClient(jamfprotect.ReportClientHeader{Header: "X-Api-Key", Value: testSecret})},
			wantValues:  [][]types.String{{null}},
			wantVersion: [][]types.String{{null}},
		},
		{
			name:        "endpoint inserted ahead",
			prior:       map[headerPosition]endpointHeaderModel{{endpoint: 0, header: 0}: writeOnlyHeader("Authorization", "1")},
			clients:     []jamfprotect.ReportClient{httpClient(auth("Bearer OTHER")), httpClient(auth(testSecret))},
			wantValues:  [][]types.String{{null}, {null}},
			wantVersion: [][]types.String{{str("1")}, {null}},
		},
		{
			name: "endpoints reordered",
			prior: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 0}: writeOnlyHeader("Authorization", "1"),
				{endpoint: 1, header: 0}: plainHeader("Authorization", "Bearer PLAIN"),
			},
			clients:     []jamfprotect.ReportClient{httpClient(auth("Bearer PLAIN")), httpClient(auth(testSecret))},
			wantValues:  [][]types.String{{null}, {null}},
			wantVersion: [][]types.String{{str("1")}, {null}},
		},
		{
			name: "same-named headers swapped",
			prior: map[headerPosition]endpointHeaderModel{
				{endpoint: 0, header: 0}: writeOnlyHeader("Authorization", "1"),
				{endpoint: 0, header: 1}: plainHeader("Authorization", "Bearer PLAIN"),
			},
			clients:     []jamfprotect.ReportClient{httpClient(auth("Bearer PLAIN"), auth(testSecret))},
			wantValues:  [][]types.String{{null, null}},
			wantVersion: [][]types.String{{str("1"), null}},
		},
		{
			name:        "same-named header inserted ahead",
			prior:       map[headerPosition]endpointHeaderModel{{endpoint: 0, header: 0}: writeOnlyHeader("Authorization", "1")},
			clients:     []jamfprotect.ReportClient{httpClient(auth("Bearer NEW"), auth(testSecret))},
			wantValues:  [][]types.String{{null, null}},
			wantVersion: [][]types.String{{str("1"), null}},
		},
		{
			name:        "plain value changed on the server",
			prior:       map[headerPosition]endpointHeaderModel{{endpoint: 0, header: 0}: plainHeader("Content-Type", "application/json")},
			clients:     []jamfprotect.ReportClient{httpClient(jamfprotect.ReportClientHeader{Header: "Content-Type", Value: "text/plain"})},
			wantValues:  [][]types.String{{null}},
			wantVersion: [][]types.String{{null}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			prior := tt.prior
			for refresh := 1; refresh <= 3; refresh++ {
				var diags diag.Diagnostics
				list := buildHTTPEndpointsState(tt.clients, prior, &diags)
				if diags.HasError() {
					t.Fatalf("refresh %d: unexpected diagnostics: %v", refresh, diags)
				}
				got := stateHeaders(t, list)
				if len(got) != len(tt.wantValues) {
					t.Fatalf("refresh %d: got %d endpoints, want %d", refresh, len(got), len(tt.wantValues))
				}
				for i := range got {
					if len(got[i]) != len(tt.wantValues[i]) {
						t.Fatalf("refresh %d endpoint %d: got %d headers, want %d", refresh, i, len(got[i]), len(tt.wantValues[i]))
					}
					for j, h := range got[i] {
						if h.Value.ValueString() == testSecret {
							t.Errorf("refresh %d endpoint %d header %d: secret stored in state", refresh, i, j)
						}
						if !h.Value.Equal(tt.wantValues[i][j]) {
							t.Errorf("refresh %d endpoint %d header %d value = %v, want %v", refresh, i, j, h.Value, tt.wantValues[i][j])
						}
						if !h.ValueWOVersion.Equal(tt.wantVersion[i][j]) {
							t.Errorf("refresh %d endpoint %d header %d value_wo_version = %v, want %v", refresh, i, j, h.ValueWOVersion, tt.wantVersion[i][j])
						}
					}
				}
				prior = priorHTTPHeaders(ctx, list, &diags)
				if diags.HasError() {
					t.Fatalf("refresh %d: priorHTTPHeaders: %v", refresh, diags)
				}
			}
		})
	}
}

// TestBuildHTTPEndpointsState_NoPriorHeaders verifies that without prior headers, as on import or
// in the list resource, no header value is read from the API.
func TestBuildHTTPEndpointsState_NoPriorHeaders(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	clients := []jamfprotect.ReportClient{httpClient(
		jamfprotect.ReportClientHeader{Header: "Authorization", Value: testSecret},
		jamfprotect.ReportClientHeader{Header: "Content-Type", Value: "application/json"},
	)}
	list := buildHTTPEndpointsState(clients, nil, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	got := stateHeaders(t, list)
	if len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("expected one endpoint with two headers, got %v", got)
	}
	for j, h := range got[0] {
		if !h.Value.IsNull() {
			t.Errorf("header %d value = %v, want null", j, h.Value)
		}
	}
}

// TestBuildHTTPEndpointsState_EndpointRecreated verifies that a refresh which persists a null
// http_endpoints, after the endpoint was deleted outside Terraform, does not let the next refresh
// store the secret when the endpoint is re-created.
func TestBuildHTTPEndpointsState_EndpointRecreated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var diags diag.Diagnostics
	prior := map[headerPosition]endpointHeaderModel{{endpoint: 0, header: 0}: writeOnlyHeader("Authorization", "1")}
	deleted := buildHTTPEndpointsState(nil, prior, &diags)
	if diags.HasError() || !deleted.IsNull() {
		t.Fatalf("expected a null list after the endpoint is deleted, got %v: %v", deleted, diags)
	}
	prior = priorHTTPHeaders(ctx, deleted, &diags)
	recreated := buildHTTPEndpointsState([]jamfprotect.ReportClient{httpClient(jamfprotect.ReportClientHeader{Header: "Authorization", Value: testSecret})}, prior, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	got := stateHeaders(t, recreated)
	if len(got) != 1 || len(got[0]) != 1 || !got[0][0].Value.IsNull() {
		t.Errorf("expected the re-created header value to stay null, got %v", got)
	}
}

// TestMatchWriteOnlyHeaders_PositionWins verifies that exact position matches are assigned before
// name fallbacks, so a fallback cannot take a prior header another API header matches exactly.
func TestMatchWriteOnlyHeaders_PositionWins(t *testing.T) {
	t.Parallel()

	woHeaders := map[headerPosition]endpointHeaderModel{
		{endpoint: 0, header: 1}: {Header: types.StringValue("Authorization"), ValueWOVersion: types.StringValue("b")},
		{endpoint: 0, header: 2}: {Header: types.StringValue("Authorization"), ValueWOVersion: types.StringValue("c")},
	}
	headers := []jamfprotect.ReportClientHeader{
		{Header: "Authorization"},
		{Header: "Authorization"},
		{Header: "Authorization"},
	}

	matched := matchWriteOnlyHeaders(headers, 0, woHeaders)
	if len(matched) != 2 {
		t.Fatalf("expected 2 matches, got %d: %v", len(matched), matched)
	}
	if got := matched[1]; got != (headerPosition{endpoint: 0, header: 1}) {
		t.Errorf("header 1 matched %v, want prior header 1", got)
	}
	if got := matched[2]; got != (headerPosition{endpoint: 0, header: 2}) {
		t.Errorf("header 2 matched %v, want prior header 2", got)
	}
	if _, ok := matched[0]; ok {
		t.Errorf("header 0 should not match, got %v", matched[0])
	}
}

// TestValidateReportClients verifies that clients the endpoint attributes cannot represent produce an error.
func TestValidateReportClients(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		types        []string
		wantErrCount int
	}{
		{
			name:  "one of each type",
			types: []string{"Http", "Kafka", "Syslog", "LogFile", "JamfCloud"},
		},
		{
			name:  "several list endpoints",
			types: []string{"Http", "Http", "Kafka", "Kafka", "Syslog", "Syslog", "JamfCloud"},
		},
		{
			name: "no clients",
		},
		{
			name:         "two jamf cloud endpoints",
			types:        []string{"JamfCloud", "Http", "JamfCloud"},
			wantErrCount: 1,
		},
		{
			name:         "three log file endpoints",
			types:        []string{"LogFile", "LogFile", "LogFile"},
			wantErrCount: 1,
		},
		{
			name:         "unknown client type",
			types:        []string{"JamfCloud", "Webhook"},
			wantErrCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clients := make([]jamfprotect.ReportClient, 0, len(tt.types))
			for _, clientType := range tt.types {
				clients = append(clients, jamfprotect.ReportClient{Type: clientType})
			}
			var diags diag.Diagnostics
			validateReportClients(clients, &diags)
			if diags.ErrorsCount() != tt.wantErrCount {
				t.Errorf("ErrorsCount() = %d, want %d: %v", diags.ErrorsCount(), tt.wantErrCount, diags)
			}
		})
	}
}

// TestApplyState_UnrepresentableClients verifies that applyState fails rather than dropping a client it cannot represent.
func TestApplyState_UnrepresentableClients(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		clients []jamfprotect.ReportClient
	}{
		{
			name: "second jamf cloud endpoint",
			clients: []jamfprotect.ReportClient{
				{Type: "JamfCloud", SupportedReports: []string{"AlertHigh"}},
				{Type: "JamfCloud", SupportedReports: []string{"AlertLow", "Telemetry"}},
			},
		},
		{
			name: "unknown report type",
			clients: []jamfprotect.ReportClient{
				{Type: "JamfCloud", SupportedReports: []string{"AlertHigh", "SomethingUnknown"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var data ActionConfigResourceModel
			var diags diag.Diagnostics
			r := ActionConfigResource{}
			r.applyState(context.Background(), &data, jamfprotect.ActionConfig{ID: "1", Name: "test", Clients: tt.clients}, &diags)
			if !diags.HasError() {
				t.Fatalf("expected an error diagnostic, got none")
			}
		})
	}
}
