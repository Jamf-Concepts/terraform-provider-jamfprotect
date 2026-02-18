// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	expNormalized := normalizeVariables(t, expected)
	actNormalized := normalizeVariables(t, actual)
	if !reflect.DeepEqual(expNormalized, actNormalized) {
		expJSON, _ := json.Marshal(expNormalized)
		actJSON, _ := json.Marshal(actNormalized)
		t.Fatalf("variables mismatch\nexpected: %s\nactual:   %s", expJSON, actJSON)
	}
}

func normalizeVariables(t *testing.T, vars map[string]any) any {
	t.Helper()
	if vars == nil {
		return nil
	}
	data, err := json.Marshal(vars)
	if err != nil {
		t.Fatalf("failed to marshal vars: %v", err)
	}
	var normalized any
	if err := json.Unmarshal(data, &normalized); err != nil {
		t.Fatalf("failed to unmarshal vars: %v", err)
	}
	return normalized
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
			if callCount == 1 {
				assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "NAME"}, req.Variables)
				return map[string]any{"data": map[string]any{"listPreventLists": map[string]any{
					"items":    []map[string]any{{"id": "pl-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "NAME", "nextToken": "next"}, req.Variables)
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
			"name":               input.Name,
			"description":        input.Description,
			"logFiles":           input.LogFiles,
			"logFileCollection":  input.LogFileCollection,
			"performanceMetrics": input.PerformanceMetrics,
			"events":             input.Events,
			"fileHashing":        input.FileHashing,
			"RBAC_Plan":          true,
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
			"id":                 "tv2-3",
			"name":               input.Name,
			"description":        input.Description,
			"logFiles":           input.LogFiles,
			"logFileCollection":  input.LogFileCollection,
			"performanceMetrics": input.PerformanceMetrics,
			"events":             input.Events,
			"fileHashing":        input.FileHashing,
			"RBAC_Plan":          true,
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
				assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "NAME", "filter": map[string]any{}}, req.Variables)
				return map[string]any{"data": map[string]any{"listUnifiedLoggingFilters": map[string]any{
					"items":    []map[string]any{{"uuid": "ulf-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "NAME", "filter": map[string]any{}, "nextToken": "next"}, req.Variables)
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
				assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "CREATED"}, req.Variables)
				return map[string]any{"data": map[string]any{"listPlans": map[string]any{
					"items":    []map[string]any{{"id": "pl-1"}},
					"pageInfo": map[string]any{"next": "next", "total": 2},
				}}}
			}
			assertVariablesEqual(t, map[string]any{"direction": "ASC", "field": "CREATED", "nextToken": "next"}, req.Variables)
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
