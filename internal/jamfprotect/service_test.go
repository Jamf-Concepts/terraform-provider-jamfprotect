// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type graphqlHandler func(t *testing.T, path string, req graphQLRequest) any

func newTestService(t *testing.T, handler graphqlHandler) (*Service, func()) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		handleGraphQL(t, w, r, handler)
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		handleGraphQL(t, w, r, handler)
	})

	srv := httptest.NewServer(mux)
	c := client.NewClient(srv.URL, "cid", "csecret")
	return NewService(c), srv.Close
}

func handleGraphQL(t *testing.T, w http.ResponseWriter, r *http.Request, handler graphqlHandler) {
	t.Helper()

	var req graphQLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		t.Fatalf("failed to decode graphql request: %v", err)
	}

	payload := handler(t, r.URL.Path, req)
	if payload == nil {
		payload = map[string]any{"data": map[string]any{}}
	}
	writeJSON(t, w, payload)
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}
}

func assertVariablesEqual(t *testing.T, expected map[string]any, actual map[string]any) {
	t.Helper()
	if len(expected) == 0 && actual == nil {
		return
	}
	if expected == nil && len(actual) == 0 {
		return
	}
	if expected == nil || actual == nil {
		t.Fatalf("expected variables %v, got %v", expected, actual)
	}
	expJSON := normalizeJSON(t, expected)
	actJSON := normalizeJSON(t, actual)
	if !bytes.Equal(expJSON, actJSON) {
		t.Fatalf("variables mismatch\nexpected: %s\nactual:   %s", expJSON, actJSON)
	}
}

// normalizeJSON marshals v, then unmarshals into any and re-marshals so that
// map key order is consistent regardless of the original type (struct vs map).
func normalizeJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var norm any
	if err := json.Unmarshal(data, &norm); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	out, err := json.Marshal(norm)
	if err != nil {
		t.Fatalf("failed to re-marshal: %v", err)
	}
	return out
}

func TestService_ActionConfig(t *testing.T) {
	input := ActionConfigInput{
		Name:        "ac-name",
		Description: "ac-desc",
		AlertConfig: map[string]any{"data": map[string]any{}},
		Clients:     []map[string]any{{"type": "http"}},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":        input.Name,
			"description": input.Description,
			"alertConfig": input.AlertConfig,
			"clients":     input.Clients,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createActionConfigs": map[string]any{"id": "ac-1"}}}
		})
		defer done()

		got, err := svc.CreateActionConfig(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "ac-1" {
			t.Fatalf("expected id ac-1, got %s", got.ID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"id": "ac-2"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getActionConfigs": map[string]any{"id": "ac-2"}}}
		})
		defer done()

		got, err := svc.GetActionConfig(context.Background(), "ac-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "ac-2" {
			t.Fatalf("expected id ac-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"id":          "ac-3",
			"name":        input.Name,
			"description": input.Description,
			"alertConfig": input.AlertConfig,
			"clients":     input.Clients,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateActionConfigs": map[string]any{"id": "ac-3"}}}
		})
		defer done()

		got, err := svc.UpdateActionConfig(context.Background(), "ac-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "ac-3" {
			t.Fatalf("expected id ac-3, got %s", got.ID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"id": "ac-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteActionConfigs": map[string]any{"id": "ac-4"}}}
		})
		defer done()

		if err := svc.DeleteActionConfig(context.Background(), "ac-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"direction": "DESC", "field": "created"}, req.Variables)
				return map[string]any{"data": map[string]any{"listActionConfigs": map[string]any{
					"items":    []map[string]any{{"id": "ac-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "DESC", "field": "created", "nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listActionConfigs": map[string]any{
				"items":    []map[string]any{{"id": "ac-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListActionConfigs(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_Analytic(t *testing.T) {
	input := AnalyticInput{
		Name:        "an-name",
		InputType:   "it",
		Description: "desc",
		Actions:     []string{"action"},
		AnalyticActions: []AnalyticActionInput{
			{Name: "aa", Parameters: "params"},
		},
		Tags:          []string{"tag"},
		Categories:    []string{"cat"},
		Filter:        "filter",
		Context:       []AnalyticContextInput{{Name: "ctx", Type: "type", Exprs: []string{"expr"}}},
		Level:         2,
		Severity:      "HIGH",
		SnapshotFiles: []string{"/tmp/file"},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":            input.Name,
			"inputType":       input.InputType,
			"description":     input.Description,
			"actions":         input.Actions,
			"analyticActions": input.AnalyticActions,
			"tags":            input.Tags,
			"categories":      input.Categories,
			"filter":          input.Filter,
			"context":         input.Context,
			"level":           input.Level,
			"severity":        input.Severity,
			"snapshotFiles":   input.SnapshotFiles,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createAnalytic": map[string]any{"uuid": "an-1"}}}
		})
		defer done()

		got, err := svc.CreateAnalytic(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "an-1" {
			t.Fatalf("expected uuid an-1, got %s", got.UUID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"uuid": "an-2"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getAnalytic": map[string]any{"uuid": "an-2"}}}
		})
		defer done()

		got, err := svc.GetAnalytic(context.Background(), "an-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.UUID != "an-2" {
			t.Fatalf("expected uuid an-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"uuid":            "an-3",
			"name":            input.Name,
			"inputType":       input.InputType,
			"description":     input.Description,
			"actions":         input.Actions,
			"analyticActions": input.AnalyticActions,
			"tags":            input.Tags,
			"categories":      input.Categories,
			"filter":          input.Filter,
			"context":         input.Context,
			"level":           input.Level,
			"severity":        input.Severity,
			"snapshotFiles":   input.SnapshotFiles,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateAnalytic": map[string]any{"uuid": "an-3"}}}
		})
		defer done()

		got, err := svc.UpdateAnalytic(context.Background(), "an-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "an-3" {
			t.Fatalf("expected uuid an-3, got %s", got.UUID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"uuid": "an-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteAnalytic": map[string]any{"uuid": "an-4"}}}
		})
		defer done()

		if err := svc.DeleteAnalytic(context.Background(), "an-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			if req.Variables != nil {
				t.Fatalf("expected nil variables, got %v", req.Variables)
			}
			return map[string]any{"data": map[string]any{"listAnalytics": map[string]any{
				"items": []map[string]any{{"uuid": "an-1"}, {"uuid": "an-2"}},
			}}}
		})
		defer done()

		items, err := svc.ListAnalytics(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_AnalyticSet(t *testing.T) {
	input := AnalyticSetInput{
		Name:        "aset",
		Description: "desc",
		Types:       []string{"event"},
		Analytics:   []string{"an-1"},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":             input.Name,
			"description":      input.Description,
			"types":            input.Types,
			"analytics":        input.Analytics,
			"RBAC_Plan":        true,
			"excludeAnalytics": false,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createAnalyticSet": map[string]any{"uuid": "as-1"}}}
		})
		defer done()

		got, err := svc.CreateAnalyticSet(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "as-1" {
			t.Fatalf("expected uuid as-1, got %s", got.UUID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{
			"uuid":             "as-2",
			"RBAC_Plan":        true,
			"excludeAnalytics": false,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getAnalyticSet": map[string]any{"uuid": "as-2"}}}
		})
		defer done()

		got, err := svc.GetAnalyticSet(context.Background(), "as-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.UUID != "as-2" {
			t.Fatalf("expected uuid as-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"uuid":             "as-3",
			"name":             input.Name,
			"description":      input.Description,
			"types":            input.Types,
			"analytics":        input.Analytics,
			"RBAC_Plan":        true,
			"excludeAnalytics": false,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateAnalyticSet": map[string]any{"uuid": "as-3"}}}
		})
		defer done()

		got, err := svc.UpdateAnalyticSet(context.Background(), "as-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "as-3" {
			t.Fatalf("expected uuid as-3, got %s", got.UUID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"uuid": "as-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteAnalyticSet": map[string]any{"uuid": "as-4"}}}
		})
		defer done()

		if err := svc.DeleteAnalyticSet(context.Background(), "as-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"RBAC_Plan": true, "excludeAnalytics": false}, req.Variables)
				return map[string]any{"data": map[string]any{"listAnalyticSets": map[string]any{
					"items":    []map[string]any{{"uuid": "as-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"RBAC_Plan": true, "excludeAnalytics": false, "nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listAnalyticSets": map[string]any{
				"items":    []map[string]any{{"uuid": "as-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListAnalyticSets(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_ExceptionSet(t *testing.T) {
	input := ExceptionSetInput{
		Name:        "es",
		Description: "desc",
		Exceptions: []ExceptionInput{{
			Type:           "APP",
			Value:          "val",
			IgnoreActivity: "NONE",
		}},
		EsExceptions: []EsExceptionInput{{
			Type:           "ES",
			Value:          "val",
			IgnoreActivity: "NONE",
		}},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":          input.Name,
			"description":   input.Description,
			"exceptions":    input.Exceptions,
			"esExceptions":  input.EsExceptions,
			"minimal":       false,
			"RBAC_Analytic": true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createExceptionSet": map[string]any{"uuid": "es-1"}}}
		})
		defer done()

		got, err := svc.CreateExceptionSet(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "es-1" {
			t.Fatalf("expected uuid es-1, got %s", got.UUID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{
			"uuid":          "es-2",
			"minimal":       false,
			"RBAC_Analytic": true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getExceptionSet": map[string]any{"uuid": "es-2"}}}
		})
		defer done()

		got, err := svc.GetExceptionSet(context.Background(), "es-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.UUID != "es-2" {
			t.Fatalf("expected uuid es-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"uuid":          "es-3",
			"name":          input.Name,
			"description":   input.Description,
			"exceptions":    input.Exceptions,
			"esExceptions":  input.EsExceptions,
			"minimal":       false,
			"RBAC_Analytic": true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateExceptionSet": map[string]any{"uuid": "es-3"}}}
		})
		defer done()

		got, err := svc.UpdateExceptionSet(context.Background(), "es-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "es-3" {
			t.Fatalf("expected uuid es-3, got %s", got.UUID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"uuid": "es-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteExceptionSet": map[string]any{"uuid": "es-4"}}}
		})
		defer done()

		if err := svc.DeleteExceptionSet(context.Background(), "es-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{}, req.Variables)
				return map[string]any{"data": map[string]any{"listExceptionSets": map[string]any{
					"items":    []map[string]any{{"uuid": "es-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listExceptionSets": map[string]any{
				"items":    []map[string]any{{"uuid": "es-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListExceptionSets(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_CustomPreventList(t *testing.T) {
	input := CustomPreventListInput{
		Name:        "pl",
		Description: "desc",
		Type:        "BLOCK",
		Tags:        []string{"tag"},
		List:        []string{"item"},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":        input.Name,
			"tags":        input.Tags,
			"type":        input.Type,
			"list":        input.List,
			"description": input.Description,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createPreventList": map[string]any{"id": "pl-1"}}}
		})
		defer done()

		got, err := svc.CreateCustomPreventList(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "pl-1" {
			t.Fatalf("expected id pl-1, got %s", got.ID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"id": "pl-2"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getPreventList": map[string]any{"id": "pl-2"}}}
		})
		defer done()

		got, err := svc.GetCustomPreventList(context.Background(), "pl-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "pl-2" {
			t.Fatalf("expected id pl-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"id":          "pl-3",
			"name":        input.Name,
			"tags":        input.Tags,
			"type":        input.Type,
			"list":        input.List,
			"description": input.Description,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updatePreventList": map[string]any{"id": "pl-3"}}}
		})
		defer done()

		got, err := svc.UpdateCustomPreventList(context.Background(), "pl-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "pl-3" {
			t.Fatalf("expected id pl-3, got %s", got.ID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"id": "pl-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deletePreventList": map[string]any{"id": "pl-4"}}}
		})
		defer done()

		if err := svc.DeleteCustomPreventList(context.Background(), "pl-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			baseVars := map[string]any{
				"direction": "DESC",
				"field":     "created",
			}
			if callCount == 1 {
				assertVariablesEqual(t, baseVars, req.Variables)
				return map[string]any{"data": map[string]any{"listPreventLists": map[string]any{
					"items":    []map[string]any{{"id": "pl-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			baseVars["nextToken"] = "next"
			assertVariablesEqual(t, baseVars, req.Variables)
			return map[string]any{"data": map[string]any{"listPreventLists": map[string]any{
				"items":    []map[string]any{{"id": "pl-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListCustomPreventLists(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_TelemetryV2(t *testing.T) {
	input := TelemetryV2Input{
		Name:               "tv2",
		Description:        "desc",
		LogFiles:           []string{"/var/log"},
		LogFileCollection:  true,
		PerformanceMetrics: false,
		Events:             []string{"EVENT"},
		FileHashing:        true,
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"input":     input,
			"RBAC_Plan": true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createTelemetryV2": map[string]any{"id": "tv2-1"}}}
		})
		defer done()

		got, err := svc.CreateTelemetryV2(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "tv2-1" {
			t.Fatalf("expected id tv2-1, got %s", got.ID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"id": "tv2-2", "RBAC_Plan": true}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getTelemetryV2": map[string]any{"id": "tv2-2"}}}
		})
		defer done()

		got, err := svc.GetTelemetryV2(context.Background(), "tv2-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "tv2-2" {
			t.Fatalf("expected id tv2-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"id":        "tv2-3",
			"input":     input,
			"RBAC_Plan": true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateTelemetryV2": map[string]any{"id": "tv2-3"}}}
		})
		defer done()

		got, err := svc.UpdateTelemetryV2(context.Background(), "tv2-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "tv2-3" {
			t.Fatalf("expected id tv2-3, got %s", got.ID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"id": "tv2-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteTelemetryV2": map[string]any{"id": "tv2-4"}}}
		})
		defer done()

		if err := svc.DeleteTelemetryV2(context.Background(), "tv2-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"direction": "DESC", "field": "created", "RBAC_Plan": true}, req.Variables)
				return map[string]any{"data": map[string]any{"listTelemetriesV2": map[string]any{
					"items":    []map[string]any{{"id": "tv2-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "DESC", "field": "created", "RBAC_Plan": true, "nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listTelemetriesV2": map[string]any{
				"items":    []map[string]any{{"id": "tv2-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListTelemetriesV2(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_RemovableStorageControlSet(t *testing.T) {
	input := RemovableStorageControlSetInput{
		Name:                 "usb",
		Description:          "desc",
		DefaultMountAction:   "READ_ONLY",
		DefaultMessageAction: "BLOCK",
		Rules: []RemovableStorageControlRuleInput{{
			Type: "vendor",
			VendorRule: &RemovableStorageControlRuleDetails{
				MountAction: "ALLOW",
				Vendors:     []string{"acme"},
			},
		}},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":                 input.Name,
			"description":          input.Description,
			"defaultMountAction":   input.DefaultMountAction,
			"defaultMessageAction": input.DefaultMessageAction,
			"rules":                input.Rules,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createUSBControlSet": map[string]any{"id": "usb-1"}}}
		})
		defer done()

		got, err := svc.CreateRemovableStorageControlSet(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "usb-1" {
			t.Fatalf("expected id usb-1, got %s", got.ID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"id": "usb-2"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getUSBControlSet": map[string]any{"id": "usb-2"}}}
		})
		defer done()

		got, err := svc.GetRemovableStorageControlSet(context.Background(), "usb-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "usb-2" {
			t.Fatalf("expected id usb-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"id":                   "usb-3",
			"name":                 input.Name,
			"description":          input.Description,
			"defaultMountAction":   input.DefaultMountAction,
			"defaultMessageAction": input.DefaultMessageAction,
			"rules":                input.Rules,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateUSBControlSet": map[string]any{"id": "usb-3"}}}
		})
		defer done()

		got, err := svc.UpdateRemovableStorageControlSet(context.Background(), "usb-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "usb-3" {
			t.Fatalf("expected id usb-3, got %s", got.ID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"id": "usb-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteUSBControlSet": map[string]any{"id": "usb-4"}}}
		})
		defer done()

		if err := svc.DeleteRemovableStorageControlSet(context.Background(), "usb-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "created"}, req.Variables)
				return map[string]any{"data": map[string]any{"listUSBControlSets": map[string]any{
					"items":    []map[string]any{{"id": "usb-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "created", "nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listUSBControlSets": map[string]any{
				"items":    []map[string]any{{"id": "usb-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListRemovableStorageControlSets(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_UnifiedLoggingFilter(t *testing.T) {
	input := UnifiedLoggingFilterInput{
		Name:        "ulf",
		Description: "desc",
		Tags:        []string{"tag"},
		Filter:      "filter",
		Enabled:     true,
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":        input.Name,
			"description": input.Description,
			"tags":        input.Tags,
			"filter":      input.Filter,
			"enabled":     input.Enabled,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createUnifiedLoggingFilter": map[string]any{"uuid": "ulf-1"}}}
		})
		defer done()

		got, err := svc.CreateUnifiedLoggingFilter(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "ulf-1" {
			t.Fatalf("expected uuid ulf-1, got %s", got.UUID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"uuid": "ulf-2"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getUnifiedLoggingFilter": map[string]any{"uuid": "ulf-2"}}}
		})
		defer done()

		got, err := svc.GetUnifiedLoggingFilter(context.Background(), "ulf-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.UUID != "ulf-2" {
			t.Fatalf("expected uuid ulf-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"uuid":        "ulf-3",
			"name":        input.Name,
			"description": input.Description,
			"tags":        input.Tags,
			"filter":      input.Filter,
			"enabled":     input.Enabled,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateUnifiedLoggingFilter": map[string]any{"uuid": "ulf-3"}}}
		})
		defer done()

		got, err := svc.UpdateUnifiedLoggingFilter(context.Background(), "ulf-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "ulf-3" {
			t.Fatalf("expected uuid ulf-3, got %s", got.UUID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"uuid": "ulf-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteUnifiedLoggingFilter": map[string]any{"uuid": "ulf-4"}}}
		})
		defer done()

		if err := svc.DeleteUnifiedLoggingFilter(context.Background(), "ulf-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/graphql" {
				t.Fatalf("expected /graphql, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "name", "filter": map[string]any{}}, req.Variables)
				return map[string]any{"data": map[string]any{"listUnifiedLoggingFilters": map[string]any{
					"items":    []map[string]any{{"uuid": "ulf-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "name", "filter": map[string]any{}, "nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listUnifiedLoggingFilters": map[string]any{
				"items":    []map[string]any{{"uuid": "ulf-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListUnifiedLoggingFilters(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_Plan(t *testing.T) {
	logLevel := "INFO"
	telemetry := "t1"
	telemetryV2 := "tv2"
	usbSet := "usb"

	input := PlanInput{
		Name:          "plan",
		Description:   "desc",
		LogLevel:      &logLevel,
		ActionConfigs: "ac-1",
		ExceptionSets: []string{"es-1"},
		Telemetry:     &telemetry,
		TelemetryV2:   &telemetryV2,
		AnalyticSets:  []PlanAnalyticSetInput{{Type: "event", UUID: "as-1"}},
		USBControlSet: &usbSet,
		CommsConfig: PlanCommsConfigInput{
			FQDN:     "example.com",
			Protocol: "https",
		},
		InfoSync: PlanInfoSyncInput{
			Attrs:                []string{"attr"},
			InsightsSyncInterval: 10,
		},
		AutoUpdate: true,
		SignaturesFeedConfig: PlanSignaturesFeedConfigInput{
			Mode: "AUTO",
		},
	}

	t.Run("Create", func(t *testing.T) {
		expected := buildPlanVariables(input)
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createPlan": map[string]any{"id": "pl-1"}}}
		})
		defer done()

		got, err := svc.CreatePlan(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "pl-1" {
			t.Fatalf("expected id pl-1, got %s", got.ID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"id": "pl-2"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getPlan": map[string]any{"id": "pl-2"}}}
		})
		defer done()

		got, err := svc.GetPlan(context.Background(), "pl-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "pl-2" {
			t.Fatalf("expected id pl-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := buildPlanVariables(input)
		expected["id"] = "pl-3"
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updatePlan": map[string]any{"id": "pl-3"}}}
		})
		defer done()

		got, err := svc.UpdatePlan(context.Background(), "pl-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "pl-3" {
			t.Fatalf("expected id pl-3, got %s", got.ID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"id": "pl-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deletePlan": map[string]any{"id": "pl-4"}}}
		})
		defer done()

		if err := svc.DeletePlan(context.Background(), "pl-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "created"}, req.Variables)
				return map[string]any{"data": map[string]any{"listPlans": map[string]any{
					"items":    []map[string]any{{"id": "pl-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "created", "nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listPlans": map[string]any{
				"items":    []map[string]any{{"id": "pl-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListPlans(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_BuildPlanVariables(t *testing.T) {
	logLevel := "DEBUG"
	telemetry := "tel"
	telemetryV2 := "tv2"
	usbSet := "usb"

	input := PlanInput{
		Name:          "plan",
		Description:   "desc",
		LogLevel:      &logLevel,
		ActionConfigs: "ac",
		ExceptionSets: []string{"es"},
		Telemetry:     &telemetry,
		TelemetryV2:   &telemetryV2,
		AnalyticSets:  []PlanAnalyticSetInput{{Type: "event", UUID: "as"}},
		USBControlSet: &usbSet,
		CommsConfig:   PlanCommsConfigInput{FQDN: "f", Protocol: "p"},
		InfoSync:      PlanInfoSyncInput{Attrs: []string{"a"}, InsightsSyncInterval: 5},
		AutoUpdate:    true,
		SignaturesFeedConfig: PlanSignaturesFeedConfigInput{
			Mode: "AUTO",
		},
	}

	vars := buildPlanVariables(input)
	assertVariablesEqual(t, map[string]any{
		"name":          "plan",
		"description":   "desc",
		"actionConfigs": "ac",
		"autoUpdate":    true,
		"logLevel":      "DEBUG",
		"exceptionSets": []string{"es"},
		"telemetry":     "tel",
		"telemetryV2":   "tv2",
		"analyticSets":  []map[string]any{{"type": "event", "uuid": "as"}},
		"usbControlSet": "usb",
		"commsConfig": map[string]any{
			"fqdn":     "f",
			"protocol": "p",
		},
		"infoSync": map[string]any{
			"attrs":                []string{"a"},
			"insightsSyncInterval": int64(5),
		},
		"signaturesFeedConfig": map[string]any{
			"mode": "AUTO",
		},
	}, vars)

	input = PlanInput{
		Name:            "plan",
		Description:     "desc",
		ActionConfigs:   "ac",
		TelemetryV2:     &telemetryV2,
		TelemetryV2Null: true,
		CommsConfig:     PlanCommsConfigInput{FQDN: "f", Protocol: "p"},
		InfoSync:        PlanInfoSyncInput{Attrs: []string{"a"}, InsightsSyncInterval: 5},
		AutoUpdate:      true,
		SignaturesFeedConfig: PlanSignaturesFeedConfigInput{
			Mode: "AUTO",
		},
	}

	vars = buildPlanVariables(input)
	if vars["telemetryV2"] != nil {
		t.Fatalf("expected telemetryV2 to be nil when TelemetryV2Null is true")
	}
}

func TestService_Downloads(t *testing.T) {
	t.Run("Get", func(t *testing.T) {
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if req.Variables != nil {
				t.Fatalf("expected nil variables, got %v", req.Variables)
			}
			return map[string]any{"data": map[string]any{"downloads": map[string]any{
				"pppc":   "pppc-data",
				"rootCA": "ca-data",
				"vanillaPackage": map[string]any{
					"version": "5.0.0",
				},
			}}}
		})
		defer done()

		got, err := svc.GetOrganizationDownloads(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.PPPC != "pppc-data" {
			t.Fatalf("expected pppc-data, got %s", got.PPPC)
		}
		if got.VanillaPackage == nil || got.VanillaPackage.Version != "5.0.0" {
			t.Fatalf("expected version 5.0.0, got %#v", got.VanillaPackage)
		}
	})
}

func TestService_ChangeManagement(t *testing.T) {
	t.Run("Get", func(t *testing.T) {
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if req.Variables != nil {
				t.Fatalf("expected nil variables, got %v", req.Variables)
			}
			return map[string]any{"data": map[string]any{"getAppInitializationData": map[string]any{
				"configFreeze": true,
			}}}
		})
		defer done()

		got, err := svc.GetConfigFreeze(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.ConfigFreeze {
			t.Fatal("expected configFreeze true")
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{"configFreeze": true}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateOrganizationConfigFreeze": map[string]any{
				"configFreeze": true,
			}}}
		})
		defer done()

		got, err := svc.UpdateOrganizationConfigFreeze(context.Background(), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.ConfigFreeze {
			t.Fatal("expected configFreeze true")
		}
	})
}

func TestService_DataRetention(t *testing.T) {
	t.Run("Get", func(t *testing.T) {
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if req.Variables != nil {
				t.Fatalf("expected nil variables, got %v", req.Variables)
			}
			return map[string]any{"data": map[string]any{"getOrganization": map[string]any{
				"retention": map[string]any{
					"database": map[string]any{
						"log":   map[string]any{"numberOfDays": 30},
						"alert": map[string]any{"numberOfDays": 60},
					},
					"cold": map[string]any{
						"alert": map[string]any{"numberOfDays": 90},
					},
					"updated": "2025-01-01",
				},
			}}}
		})
		defer done()

		got, err := svc.GetDataRetention(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Database.Log.NumberOfDays != 30 {
			t.Fatalf("expected log days 30, got %d", got.Database.Log.NumberOfDays)
		}
		if got.Database.Alert.NumberOfDays != 60 {
			t.Fatalf("expected alert days 60, got %d", got.Database.Alert.NumberOfDays)
		}
		if got.Cold.Alert.NumberOfDays != 90 {
			t.Fatalf("expected cold alert days 90, got %d", got.Cold.Alert.NumberOfDays)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"databaseLogDays":   int64(30),
			"databaseAlertDays": int64(60),
			"coldAlertDays":     int64(90),
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateOrganizationRetention": map[string]any{
				"retention": map[string]any{
					"database": map[string]any{
						"log":   map[string]any{"numberOfDays": 30},
						"alert": map[string]any{"numberOfDays": 60},
					},
					"cold": map[string]any{
						"alert": map[string]any{"numberOfDays": 90},
					},
					"updated": "2025-01-02",
				},
			}}}
		})
		defer done()

		input := DataRetentionInput{
			DatabaseLogDays:   30,
			DatabaseAlertDays: 60,
			ColdAlertDays:     90,
		}
		got, err := svc.UpdateDataRetention(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Database.Log.NumberOfDays != 30 {
			t.Fatalf("expected log days 30, got %d", got.Database.Log.NumberOfDays)
		}
	})
}

func TestService_DataForwarding(t *testing.T) {
	t.Run("Get", func(t *testing.T) {
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if req.Variables != nil {
				t.Fatalf("expected nil variables, got %v", req.Variables)
			}
			return map[string]any{"data": map[string]any{"getOrganization": map[string]any{
				"uuid": "org-1",
				"forward": map[string]any{
					"s3":         map[string]any{"bucket": "my-bucket", "enabled": true},
					"sentinel":   map[string]any{"enabled": false},
					"sentinelV2": map[string]any{"enabled": false},
				},
			}}}
		})
		defer done()

		got, err := svc.GetDataForwarding(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "org-1" {
			t.Fatalf("expected uuid org-1, got %s", got.UUID)
		}
		if got.Forward.S3.Bucket != "my-bucket" {
			t.Fatalf("expected bucket my-bucket, got %s", got.Forward.S3.Bucket)
		}
	})

	t.Run("Update", func(t *testing.T) {
		input := DataForwardingInput{
			S3:       ForwardS3Input{Bucket: "bucket", Enabled: true, Encrypted: true, Prefix: "pre", Role: "role"},
			Sentinel: ForwardSentinelInput{Enabled: false},
			SentinelV2: ForwardSentinelV2Input{
				Enabled:       true,
				AzureTenantID: "tenant",
				AzureClientID: "client",
				Endpoint:      "https://ep",
			},
		}
		expected := map[string]any{
			"s3":         input.S3,
			"sentinel":   input.Sentinel,
			"sentinelV2": input.SentinelV2,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateOrganizationForward": map[string]any{
				"uuid": "org-1",
				"forward": map[string]any{
					"s3":         map[string]any{"bucket": "bucket", "enabled": true},
					"sentinel":   map[string]any{"enabled": false},
					"sentinelV2": map[string]any{"enabled": true},
				},
			}}}
		})
		defer done()

		got, err := svc.UpdateDataForwarding(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.UUID != "org-1" {
			t.Fatalf("expected uuid org-1, got %s", got.UUID)
		}
	})
}

func TestService_Role(t *testing.T) {
	input := RoleInput{
		Name:           "admin",
		ReadResources:  []string{"COMPUTER", "PLAN"},
		WriteResources: []string{"PLAN"},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":           input.Name,
			"readResources":  input.ReadResources,
			"writeResources": input.WriteResources,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createRole": map[string]any{"id": "r-1"}}}
		})
		defer done()

		got, err := svc.CreateRole(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "r-1" {
			t.Fatalf("expected id r-1, got %s", got.ID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"id": "r-2"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getRole": map[string]any{"id": "r-2"}}}
		})
		defer done()

		got, err := svc.GetRole(context.Background(), "r-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "r-2" {
			t.Fatalf("expected id r-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"id":             "r-3",
			"name":           input.Name,
			"readResources":  input.ReadResources,
			"writeResources": input.WriteResources,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateRole": map[string]any{"id": "r-3"}}}
		})
		defer done()

		got, err := svc.UpdateRole(context.Background(), "r-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "r-3" {
			t.Fatalf("expected id r-3, got %s", got.ID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"id": "r-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteRole": map[string]any{"id": "r-4"}}}
		})
		defer done()

		if err := svc.DeleteRole(context.Background(), "r-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"pageSize": 100, "direction": "ASC", "field": "name"}, req.Variables)
				return map[string]any{"data": map[string]any{"listRoles": map[string]any{
					"items":    []map[string]any{{"id": "r-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"pageSize": 100, "direction": "ASC", "field": "name", "nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listRoles": map[string]any{
				"items":    []map[string]any{{"id": "r-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListRoles(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_User(t *testing.T) {
	connID := "conn-1"
	input := UserInput{
		Email:                 "test@example.com",
		RoleIDs:               []string{"r-1"},
		GroupIDs:              []string{"g-1"},
		ConnectionID:          &connID,
		ReceiveEmailAlert:     true,
		EmailAlertMinSeverity: "HIGH",
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"email":                 "test@example.com",
			"roleIds":               input.RoleIDs,
			"groupIds":              input.GroupIDs,
			"connectionId":          "conn-1",
			"receiveEmailAlert":     true,
			"emailAlertMinSeverity": "HIGH",
			"hasLimitedAppAccess":   false,
			"RBAC_Connection":       true,
			"RBAC_Role":             true,
			"RBAC_Group":            true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createUser": map[string]any{"id": "u-1"}}}
		})
		defer done()

		got, err := svc.CreateUser(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "u-1" {
			t.Fatalf("expected id u-1, got %s", got.ID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{
			"id":                  "u-2",
			"hasLimitedAppAccess": false,
			"RBAC_Connection":     true,
			"RBAC_Role":           true,
			"RBAC_Group":          true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getUser": map[string]any{"id": "u-2"}}}
		})
		defer done()

		got, err := svc.GetUser(context.Background(), "u-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "u-2" {
			t.Fatalf("expected id u-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"id":                    "u-3",
			"email":                 "test@example.com",
			"roleIds":               input.RoleIDs,
			"groupIds":              input.GroupIDs,
			"connectionId":          "conn-1",
			"receiveEmailAlert":     true,
			"emailAlertMinSeverity": "HIGH",
			"hasLimitedAppAccess":   false,
			"RBAC_Connection":       true,
			"RBAC_Role":             true,
			"RBAC_Group":            true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateUser": map[string]any{"id": "u-3"}}}
		})
		defer done()

		got, err := svc.UpdateUser(context.Background(), "u-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "u-3" {
			t.Fatalf("expected id u-3, got %s", got.ID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"id": "u-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteUser": map[string]any{"id": "u-4"}}}
		})
		defer done()

		if err := svc.DeleteUser(context.Background(), "u-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			baseVars := map[string]any{
				"pageSize":            100,
				"direction":           "ASC",
				"field":               "email",
				"hasLimitedAppAccess": false,
				"RBAC_Connection":     true,
				"RBAC_Role":           true,
				"RBAC_Group":          true,
			}
			if callCount == 1 {
				assertVariablesEqual(t, baseVars, req.Variables)
				return map[string]any{"data": map[string]any{"listUsers": map[string]any{
					"items":    []map[string]any{{"id": "u-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			baseVars["nextToken"] = "next"
			assertVariablesEqual(t, baseVars, req.Variables)
			return map[string]any{"data": map[string]any{"listUsers": map[string]any{
				"items":    []map[string]any{{"id": "u-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListUsers(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_User_NoConnectionID(t *testing.T) {
	input := UserInput{
		Email:                 "no-conn@example.com",
		RoleIDs:               []string{"r-1"},
		GroupIDs:              []string{},
		ReceiveEmailAlert:     false,
		EmailAlertMinSeverity: "LOW",
	}

	expected := map[string]any{
		"email":                 "no-conn@example.com",
		"roleIds":               input.RoleIDs,
		"groupIds":              input.GroupIDs,
		"connectionId":          nil,
		"receiveEmailAlert":     false,
		"emailAlertMinSeverity": "LOW",
		"hasLimitedAppAccess":   false,
		"RBAC_Connection":       true,
		"RBAC_Role":             true,
		"RBAC_Group":            true,
	}
	svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
		assertVariablesEqual(t, expected, req.Variables)
		return map[string]any{"data": map[string]any{"createUser": map[string]any{"id": "u-nc"}}}
	})
	defer done()

	got, err := svc.CreateUser(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "u-nc" {
		t.Fatalf("expected id u-nc, got %s", got.ID)
	}
}

func TestService_Group(t *testing.T) {
	connID := "conn-1"
	input := GroupInput{
		Name:         "admins",
		ConnectionID: &connID,
		AccessGroup:  true,
		RoleIDs:      []string{"r-1"},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":            input.Name,
			"roleIds":         input.RoleIDs,
			"accessGroup":     true,
			"connectionId":    "conn-1",
			"RBAC_Connection": true,
			"RBAC_Role":       true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createGroup": map[string]any{"id": "g-1"}}}
		})
		defer done()

		got, err := svc.CreateGroup(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "g-1" {
			t.Fatalf("expected id g-1, got %s", got.ID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{
			"id":              "g-2",
			"RBAC_Connection": true,
			"RBAC_Role":       true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getGroup": map[string]any{"id": "g-2"}}}
		})
		defer done()

		got, err := svc.GetGroup(context.Background(), "g-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "g-2" {
			t.Fatalf("expected id g-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"id":              "g-3",
			"name":            input.Name,
			"roleIds":         input.RoleIDs,
			"accessGroup":     true,
			"connectionId":    "conn-1",
			"RBAC_Connection": true,
			"RBAC_Role":       true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateGroup": map[string]any{"id": "g-3"}}}
		})
		defer done()

		got, err := svc.UpdateGroup(context.Background(), "g-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != "g-3" {
			t.Fatalf("expected id g-3, got %s", got.ID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"id": "g-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteGroup": map[string]any{"id": "g-4"}}}
		})
		defer done()

		if err := svc.DeleteGroup(context.Background(), "g-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			baseVars := map[string]any{
				"pageSize":        100,
				"direction":       "ASC",
				"field":           "name",
				"RBAC_Connection": true,
				"RBAC_Role":       true,
			}
			if callCount == 1 {
				assertVariablesEqual(t, baseVars, req.Variables)
				return map[string]any{"data": map[string]any{"listGroups": map[string]any{
					"items":    []map[string]any{{"id": "g-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			baseVars["nextToken"] = "next"
			assertVariablesEqual(t, baseVars, req.Variables)
			return map[string]any{"data": map[string]any{"listGroups": map[string]any{
				"items":    []map[string]any{{"id": "g-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListGroups(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_Group_NoConnectionID(t *testing.T) {
	input := GroupInput{
		Name:        "viewers",
		AccessGroup: false,
		RoleIDs:     []string{"r-2"},
	}

	expected := map[string]any{
		"name":            "viewers",
		"roleIds":         input.RoleIDs,
		"accessGroup":     false,
		"connectionId":    nil,
		"RBAC_Connection": true,
		"RBAC_Role":       true,
	}
	svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
		assertVariablesEqual(t, expected, req.Variables)
		return map[string]any{"data": map[string]any{"createGroup": map[string]any{"id": "g-nc"}}}
	})
	defer done()

	got, err := svc.CreateGroup(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "g-nc" {
		t.Fatalf("expected id g-nc, got %s", got.ID)
	}
}

func TestService_ApiClient(t *testing.T) {
	input := ApiClientInput{
		Name:    "my-client",
		RoleIDs: []string{"r-1", "r-2"},
	}

	t.Run("Create", func(t *testing.T) {
		expected := map[string]any{
			"name":    input.Name,
			"roleIds": input.RoleIDs,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"createApiClient": map[string]any{"clientId": "ac-1"}}}
		})
		defer done()

		got, err := svc.CreateApiClient(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ClientID != "ac-1" {
			t.Fatalf("expected clientId ac-1, got %s", got.ClientID)
		}
	})

	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{"clientId": "ac-2"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getApiClient": map[string]any{"clientId": "ac-2"}}}
		})
		defer done()

		got, err := svc.GetApiClient(context.Background(), "ac-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ClientID != "ac-2" {
			t.Fatalf("expected clientId ac-2, got %#v", got)
		}
	})

	t.Run("Update", func(t *testing.T) {
		expected := map[string]any{
			"clientId": "ac-3",
			"name":     input.Name,
			"roleIds":  input.RoleIDs,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"updateApiClient": map[string]any{"clientId": "ac-3"}}}
		})
		defer done()

		got, err := svc.UpdateApiClient(context.Background(), "ac-3", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ClientID != "ac-3" {
			t.Fatalf("expected clientId ac-3, got %s", got.ClientID)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		expected := map[string]any{"clientId": "ac-4"}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"deleteApiClient": map[string]any{"clientId": "ac-4"}}}
		})
		defer done()

		if err := svc.DeleteApiClient(context.Background(), "ac-4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		callCount := 0
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			callCount++
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"direction": "DESC", "field": "created"}, req.Variables)
				return map[string]any{"data": map[string]any{"listApiClients": map[string]any{
					"items":    []map[string]any{{"clientId": "ac-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "DESC", "field": "created", "nextToken": "next"}, req.Variables)
			return map[string]any{"data": map[string]any{"listApiClients": map[string]any{
				"items":    []map[string]any{{"clientId": "ac-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListApiClients(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}

func TestService_Computer(t *testing.T) {
	t.Run("Get", func(t *testing.T) {
		expected := map[string]any{
			"uuid":                         "comp-1",
			"isList":                       false,
			"RBAC_ThreatPreventionVersion": true,
			"RBAC_Plan":                    true,
			"RBAC_Insight":                 true,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"getComputer": map[string]any{"uuid": "comp-1", "hostName": "mac1"}}}
		})
		defer done()

		got, err := svc.GetComputer(context.Background(), "comp-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || *got.UUID != "comp-1" {
			t.Fatalf("expected uuid comp-1, got %#v", got)
		}
		if *got.HostName != "mac1" {
			t.Fatalf("expected hostName mac1, got %s", *got.HostName)
		}
	})

	t.Run("List", func(t *testing.T) {
		expected := map[string]any{
			"isList":                       true,
			"RBAC_Insight":                 true,
			"RBAC_Plan":                    true,
			"RBAC_ThreatPreventionVersion": true,
			"nextToken":                    nil,
			"pageSize":                     100,
			"direction":                    "ASC",
			"field":                        []any{"hostName"},
			"filter":                       nil,
		}
		svc, done := newTestService(t, func(t *testing.T, path string, req graphQLRequest) any {
			if path != "/app" {
				t.Fatalf("expected /app, got %s", path)
			}
			assertVariablesEqual(t, expected, req.Variables)
			return map[string]any{"data": map[string]any{"listComputers": map[string]any{
				"items":    []map[string]any{{"uuid": "c-1"}, {"uuid": "c-2"}},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			}}}
		})
		defer done()

		items, err := svc.ListComputers(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
	})
}
