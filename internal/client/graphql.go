// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"encoding/json"
	"fmt"
	"strings"
)

// graphQLRequest represents a GraphQL request payload.
type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

// graphQLResponse represents a GraphQL response payload, including any errors.
type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []graphQLError  `json:"errors"`
}

// graphQLError represents an individual error returned by the GraphQL API, including message, locations, path, and extensions.
type graphQLError struct {
	Message    string            `json:"message"`
	Locations  []graphQLLocation `json:"locations,omitempty"`
	Path       []any             `json:"path,omitempty"`
	Extensions map[string]any    `json:"extensions,omitempty"`
}

// graphQLLocation represents the line and column of an error in a GraphQL query.
type graphQLLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// mapGraphQLErrors converts a slice of graphQLError into a single error, combining messages and checking for "not found" indications.
func mapGraphQLErrors(errs []graphQLError) error {
	if len(errs) == 0 {
		return nil
	}
	messages := make([]string, 0, len(errs))
	isNotFound := false
	for _, e := range errs {
		if e.Message == "" {
			continue
		}
		lower := strings.ToLower(e.Message)
		if strings.Contains(lower, "not found") || strings.Contains(lower, "not_found") {
			isNotFound = true
		}
		msg := e.Message
		if len(e.Path) > 0 {
			msg = fmt.Sprintf("%s (path: %s)", msg, formatGraphQLPath(e.Path))
		}
		if len(e.Locations) > 0 {
			msg = fmt.Sprintf("%s (locations: %s)", msg, formatGraphQLLocations(e.Locations))
		}
		if ext := formatGraphQLExtensions(e.Extensions); ext != "" {
			msg = fmt.Sprintf("%s (extensions: %s)", msg, ext)
		}
		messages = append(messages, msg)
	}
	if len(messages) == 0 {
		return ErrGraphQL
	}

	errMsg := strings.Join(messages, "; ")
	if isNotFound {
		return fmt.Errorf("%w: %w: %s", ErrNotFound, ErrGraphQL, errMsg)
	}
	return fmt.Errorf("%w: %s", ErrGraphQL, errMsg)
}

// formatGraphQLPath converts a GraphQL error path (which can contain strings and numbers) into a readable string format.
func formatGraphQLPath(path []any) string {
	parts := make([]string, 0, len(path))
	for _, p := range path {
		switch v := p.(type) {
		case string:
			parts = append(parts, v)
		case float64:
			parts = append(parts, fmt.Sprintf("%d", int64(v)))
		default:
			parts = append(parts, fmt.Sprintf("%v", v))
		}
	}
	return strings.Join(parts, ".")
}

// formatGraphQLExtensions converts the extensions map of a GraphQL error into a JSON string for easier readability in error messages.
func formatGraphQLExtensions(ext map[string]any) string {
	if len(ext) == 0 {
		return ""
	}
	data, err := json.Marshal(ext)
	if err != nil {
		return ""
	}
	return string(data)
}

// formatGraphQLLocations converts a slice of graphQLLocation into a readable string format, showing line and column numbers.
func formatGraphQLLocations(locations []graphQLLocation) string {
	parts := make([]string, 0, len(locations))
	for _, loc := range locations {
		parts = append(parts, fmt.Sprintf("%d:%d", loc.Line, loc.Column))
	}
	return strings.Join(parts, ", ")
}
