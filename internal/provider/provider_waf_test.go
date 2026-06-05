// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// wafHTML is a representative HTML response as returned by the Jamf Protect WAF
// when it intercepts a request from a blocked IP or User-Agent — a 200 OK with
// the tenant SPA shell instead of the expected JSON token response.
const wafHTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width,initial-scale=1.0" />
    <link rel="icon" href="/favicon.png" />
    <title>Jamf Protect</title>
  </head>
  <body><div id="app"></div></body>
</html>`

// nullProviderConfig constructs a tfsdk.Config with all attributes null so that
// Configure falls through to environment-variable resolution.
func nullProviderConfig(t *testing.T) tfsdk.Config {
	t.Helper()
	ctx := context.Background()
	p := New("test")()
	schemaResp := &provider.SchemaResponse{}
	p.Schema(ctx, provider.SchemaRequest{}, schemaResp)

	raw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"url":                     tftypes.String,
			"client_id":               tftypes.String,
			"client_secret":           tftypes.String,
			"min_request_interval_ms": tftypes.Number,
		},
	}, map[string]tftypes.Value{
		"url":                     tftypes.NewValue(tftypes.String, nil),
		"client_id":               tftypes.NewValue(tftypes.String, nil),
		"client_secret":           tftypes.NewValue(tftypes.String, nil),
		"min_request_interval_ms": tftypes.NewValue(tftypes.Number, nil),
	})

	return tfsdk.Config{Raw: raw, Schema: schemaResp.Schema}
}

// TestAcc_WAF_ProviderConfigure_BlockedHTML verifies the full Terraform diagnostic
// emitted when the provider's Configure step hits a WAF-blocked endpoint that
// returns an HTML page instead of a JSON token response.
//
// Run with -v to print the verbatim diagnostic detail as it would appear in a
// Terraform plan/apply log (e.g. in CI/CD output).
func TestAcc_WAF_ProviderConfigure_BlockedHTML(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(wafHTML)); err != nil {
			t.Errorf("writing WAF response: %v", err)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("JAMFPROTECT_URL", srv.URL)
	t.Setenv("JAMFPROTECT_CLIENT_ID", "test-client-id")
	t.Setenv("JAMFPROTECT_CLIENT_SECRET", "test-secret")

	p := New("test")()
	resp := &provider.ConfigureResponse{}
	p.Configure(context.Background(), provider.ConfigureRequest{
		Config: nullProviderConfig(t),
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected Configure to produce an error diagnostic, got none")
	}

	diags := resp.Diagnostics.Errors()
	if len(diags) == 0 {
		t.Fatal("expected at least one error diagnostic")
	}

	summary := diags[0].Summary()
	detail := diags[0].Detail()

	t.Logf("\n--- verbatim diagnostic (provider Configure blocked by WAF) ---\nSummary: %s\nDetail:\n%s\n---",
		summary, detail)

	if summary != "Jamf Protect authentication failed" {
		t.Errorf("unexpected summary: %q", summary)
	}
	for _, want := range []string{
		"HTML page",
		"Contact Jamf Support",
		"Timestamp:",
		"Instance URL:",
		"Egress IP:",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail missing expected phrase %q\nfull detail:\n%s", want, detail)
		}
	}
}
