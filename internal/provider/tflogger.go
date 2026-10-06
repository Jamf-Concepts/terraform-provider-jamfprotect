// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// Ensure TerraformLogger implements jamfprotect.Logger interface.
var _ jamfprotect.Logger = (*TerraformLogger)(nil)

// maskedValue replaces secret values in logged messages and fields, matching
// the replacement terraform-plugin-log uses for its own masking.
const maskedValue = "***"

// maxLoggedResponseBody is the number of response body bytes logged before
// the body is truncated.
const maxLoggedResponseBody = 5000

// TerraformLogger implements the jamfprotect.Logger interface using tflog. It
// masks the provider's configured secrets in every message and field it logs,
// on top of the redaction the SDK applies before calling it.
type TerraformLogger struct {
	secrets []string
}

// NewTerraformLogger creates a TerraformLogger that masks the given secrets.
// Empty secrets are ignored.
func NewTerraformLogger(secrets ...string) *TerraformLogger {
	return &TerraformLogger{
		secrets: slices.DeleteFunc(slices.Clone(secrets), func(s string) bool { return s == "" }),
	}
}

// LogRequest logs HTTP request details using tflog at DEBUG level.
func (l *TerraformLogger) LogRequest(ctx context.Context, method, url string, headers http.Header, body []byte) {
	ctx = tflog.MaskLogStrings(ctx, l.secrets...)
	fields := map[string]any{
		"method": method,
		"url":    l.mask(url),
	}

	if len(headers) > 0 {
		fields["request_headers"] = l.maskHeaders(headers)
	}
	if len(body) > 0 {
		fields["request_body"] = l.mask(string(body))
	}

	tflog.Debug(ctx, "HTTP Request", fields)
}

// LogResponse logs HTTP response details using tflog at DEBUG level.
func (l *TerraformLogger) LogResponse(ctx context.Context, statusCode int, headers http.Header, body []byte) {
	ctx = tflog.MaskLogStrings(ctx, l.secrets...)
	fields := map[string]any{
		"status_code": statusCode,
	}

	if len(headers) > 0 {
		fields["response_headers"] = l.maskHeaders(headers)
	}

	if len(body) > 0 {
		bodyStr := l.mask(string(body))
		if len(bodyStr) > maxLoggedResponseBody {
			bodyStr = bodyStr[:maxLoggedResponseBody] + "... (truncated)"
		}
		fields["response_body"] = bodyStr
	}

	tflog.Debug(ctx, "HTTP Response", fields)
}

// mask replaces every configured secret in s.
func (l *TerraformLogger) mask(s string) string {
	for _, secret := range l.secrets {
		s = strings.ReplaceAll(s, secret, maskedValue)
	}
	return s
}

// maskHeaders returns a copy of headers with every configured secret masked.
// tflog masking applies only to string fields, so header maps are masked here.
func (l *TerraformLogger) maskHeaders(headers http.Header) http.Header {
	masked := headers.Clone()
	for _, values := range masked {
		for i, v := range values {
			values[i] = l.mask(v)
		}
	}
	return masked
}
