// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-log/tflogtest"
)

// testLoggerSecret is a synthetic client secret used to check masking.
const testLoggerSecret = "tf-test-client-secret-value"

// TestTerraformLogger_MasksSecrets verifies that configured secrets never reach the log output.
func TestTerraformLogger_MasksSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		log  func(ctx context.Context, l *TerraformLogger)
	}{
		{
			name: "request header",
			log: func(ctx context.Context, l *TerraformLogger) {
				l.LogRequest(ctx, http.MethodPost, "https://example.com/app", http.Header{"Authorization": {"Bearer " + testLoggerSecret}}, nil)
			},
		},
		{
			name: "request body",
			log: func(ctx context.Context, l *TerraformLogger) {
				l.LogRequest(ctx, http.MethodPost, "https://example.com/token", nil, []byte(`{"client_id":"id","password":"`+testLoggerSecret+`"}`))
			},
		},
		{
			name: "request url",
			log: func(ctx context.Context, l *TerraformLogger) {
				l.LogRequest(ctx, http.MethodGet, "https://example.com/app?secret="+testLoggerSecret, nil, nil)
			},
		},
		{
			name: "response header",
			log: func(ctx context.Context, l *TerraformLogger) {
				l.LogResponse(ctx, http.StatusOK, http.Header{"X-Echo": {testLoggerSecret}}, nil)
			},
		},
		{
			name: "response body",
			log: func(ctx context.Context, l *TerraformLogger) {
				l.LogResponse(ctx, http.StatusOK, nil, []byte(`{"data":{"secret":"`+testLoggerSecret+`"}}`))
			},
		},
		{
			name: "response body secret across the truncation point",
			log: func(ctx context.Context, l *TerraformLogger) {
				body := strings.Repeat("a", maxLoggedResponseBody-5) + testLoggerSecret
				l.LogResponse(ctx, http.StatusOK, nil, []byte(body))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			ctx := tflogtest.RootLogger(context.Background(), &out)
			tt.log(ctx, NewTerraformLogger(testLoggerSecret))

			if out.Len() == 0 {
				t.Fatal("expected log output")
			}
			if strings.Contains(out.String(), testLoggerSecret) || strings.Contains(out.String(), testLoggerSecret[:16]) {
				t.Errorf("log output contains the secret: %s", out.String())
			}
			if !strings.Contains(out.String(), maskedValue) {
				t.Errorf("log output does not contain the mask: %s", out.String())
			}
		})
	}
}

// TestTerraformLogger_EmptySecretIgnored verifies that an empty secret does not alter log output.
func TestTerraformLogger_EmptySecretIgnored(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	ctx := tflogtest.RootLogger(context.Background(), &out)
	NewTerraformLogger("").LogRequest(ctx, http.MethodPost, "https://example.com/app", nil, []byte(`{"query":"q"}`))

	if strings.Contains(out.String(), maskedValue) {
		t.Errorf("log output masked with an empty secret: %s", out.String())
	}
	if !strings.Contains(out.String(), `{\"query\":\"q\"}`) {
		t.Errorf("log output is missing the request body: %s", out.String())
	}
}
