// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"errors"
	"strings"
	"testing"
)

func TestMapGraphQLErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		errors       []graphQLError
		wantNil      bool
		wantNotFound bool
		wantGraphQL  bool
		wantContains []string
	}{
		{
			name:    "nil errors returns nil",
			errors:  nil,
			wantNil: true,
		},
		{
			name:    "empty errors returns nil",
			errors:  []graphQLError{},
			wantNil: true,
		},
		{
			name:         "single error with message",
			errors:       []graphQLError{{Message: "something went wrong"}},
			wantGraphQL:  true,
			wantContains: []string{"something went wrong"},
		},
		{
			name:         "not found lowercase",
			errors:       []graphQLError{{Message: "resource not found"}},
			wantNotFound: true,
			wantGraphQL:  true,
			wantContains: []string{"resource not found"},
		},
		{
			name:         "not_found with underscore",
			errors:       []graphQLError{{Message: "error: not_found"}},
			wantNotFound: true,
			wantGraphQL:  true,
		},
		{
			name:         "not found case insensitive",
			errors:       []graphQLError{{Message: "Resource Not Found"}},
			wantNotFound: true,
			wantGraphQL:  true,
		},
		{
			name: "multiple errors joined",
			errors: []graphQLError{
				{Message: "first error"},
				{Message: "second error"},
			},
			wantGraphQL:  true,
			wantContains: []string{"first error", "second error", ";"},
		},
		{
			name:        "empty message skipped",
			errors:      []graphQLError{{Message: ""}},
			wantGraphQL: true,
			wantNil:     false,
		},
		{
			name: "all empty messages returns bare ErrGraphQL",
			errors: []graphQLError{
				{Message: ""},
				{Message: ""},
			},
			wantGraphQL: true,
		},
		{
			name: "error with path",
			errors: []graphQLError{
				{Message: "bad field", Path: []any{"query", "getUser"}},
			},
			wantGraphQL:  true,
			wantContains: []string{"path: query.getUser"},
		},
		{
			name: "error with locations",
			errors: []graphQLError{
				{Message: "syntax error", Locations: []graphQLLocation{{Line: 1, Column: 5}}},
			},
			wantGraphQL:  true,
			wantContains: []string{"locations: 1:5"},
		},
		{
			name: "error with extensions",
			errors: []graphQLError{
				{Message: "ext error", Extensions: map[string]any{"code": "FORBIDDEN"}},
			},
			wantGraphQL:  true,
			wantContains: []string{"extensions:", "FORBIDDEN"},
		},
		{
			name: "error with all fields",
			errors: []graphQLError{
				{
					Message:    "full error",
					Path:       []any{"mutation", "createUser"},
					Locations:  []graphQLLocation{{Line: 3, Column: 10}},
					Extensions: map[string]any{"code": "BAD_INPUT"},
				},
			},
			wantGraphQL:  true,
			wantContains: []string{"full error", "path:", "locations:", "extensions:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := mapGraphQLErrors(tt.errors)

			if tt.wantNil {
				if len(tt.errors) == 0 {
					if err != nil {
						t.Fatalf("expected nil, got %v", err)
					}
					return
				}
			}

			if tt.wantGraphQL {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrGraphQL) {
					t.Errorf("expected ErrGraphQL, got %v", err)
				}
			}

			if tt.wantNotFound {
				if !errors.Is(err, ErrNotFound) {
					t.Errorf("expected ErrNotFound, got %v", err)
				}
			} else if err != nil && errors.Is(err, ErrNotFound) {
				t.Errorf("did not expect ErrNotFound, but got it")
			}

			for _, s := range tt.wantContains {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("expected error to contain %q, got %q", s, err.Error())
				}
			}
		})
	}
}

func TestFormatGraphQLPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     []any
		expected string
	}{
		{"string elements", []any{"query", "getUser"}, "query.getUser"},
		{"numeric index", []any{"errors", float64(0), "message"}, "errors.0.message"},
		{"mixed types", []any{"data", float64(2), "field"}, "data.2.field"},
		{"empty path", []any{}, ""},
		{"single element", []any{"root"}, "root"},
		{"unknown type fallback", []any{true}, "true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatGraphQLPath(tt.path)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestFormatGraphQLExtensions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ext      map[string]any
		expected string
	}{
		{"nil map", nil, ""},
		{"empty map", map[string]any{}, ""},
		{"single key", map[string]any{"code": "NOT_FOUND"}, `{"code":"NOT_FOUND"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatGraphQLExtensions(tt.ext)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}

	// Multiple keys — just verify it's valid JSON containing both keys.
	t.Run("multiple keys", func(t *testing.T) {
		t.Parallel()
		got := formatGraphQLExtensions(map[string]any{"code": "ERR", "detail": "msg"})
		if !strings.Contains(got, `"code"`) || !strings.Contains(got, `"detail"`) {
			t.Errorf("expected both keys in output, got %q", got)
		}
	})
}

func TestFormatGraphQLLocations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		locations []graphQLLocation
		expected  string
	}{
		{"single location", []graphQLLocation{{Line: 1, Column: 5}}, "1:5"},
		{"multiple locations", []graphQLLocation{{Line: 1, Column: 5}, {Line: 3, Column: 10}}, "1:5, 3:10"},
		{"empty slice", []graphQLLocation{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatGraphQLLocations(tt.locations)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
