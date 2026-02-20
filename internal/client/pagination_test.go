// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testItem struct {
	ID string `json:"id"`
}

// newTestPaginationClient creates a test client and HTTP server for pagination tests.
func newTestPaginationClient(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", handler)

	srv := httptest.NewServer(mux)
	c := NewClient(srv.URL, "cid", "csecret")
	return c, srv.Close
}

func TestListAll_SinglePage(t *testing.T) {
	t.Parallel()

	c, done := newTestPaginationClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		testEncodeJSON(t, w, map[string]any{
			"data": map[string]any{
				"listThings": map[string]any{
					"items":    []map[string]any{{"id": "a"}, {"id": "b"}},
					"pageInfo": map[string]any{"next": nil, "total": 2},
				},
			},
		})
	})
	defer done()

	items, err := ListAll[testItem](context.Background(), c, "/app", "query { listThings }", nil, "listThings")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].ID != "a" || items[1].ID != "b" {
		t.Errorf("unexpected items: %+v", items)
	}
}

func TestListAll_MultiPage(t *testing.T) {
	t.Parallel()

	callCount := 0
	c, done := newTestPaginationClient(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var req graphQLRequest
		testDecodeJSON(t, r, &req)

		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			if _, ok := req.Variables["nextToken"]; ok {
				t.Error("page 1 should not have nextToken")
			}
			testEncodeJSON(t, w, map[string]any{
				"data": map[string]any{
					"listThings": map[string]any{
						"items":    []map[string]any{{"id": "a"}},
						"pageInfo": map[string]any{"next": "cursor1", "total": 2},
					},
				},
			})
			return
		}
		if req.Variables["nextToken"] != "cursor1" {
			t.Errorf("page 2 expected nextToken=cursor1, got %v", req.Variables["nextToken"])
		}
		testEncodeJSON(t, w, map[string]any{
			"data": map[string]any{
				"listThings": map[string]any{
					"items":    []map[string]any{{"id": "b"}},
					"pageInfo": map[string]any{"next": nil, "total": 2},
				},
			},
		})
	})
	defer done()

	items, err := ListAll[testItem](context.Background(), c, "/app", "query { listThings }", map[string]any{"pageSize": 1}, "listThings")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].ID != "a" || items[1].ID != "b" {
		t.Errorf("unexpected items: %+v", items)
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls, got %d", callCount)
	}
}

func TestListAll_EmptyResult(t *testing.T) {
	t.Parallel()

	c, done := newTestPaginationClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		testEncodeJSON(t, w, map[string]any{
			"data": map[string]any{
				"listThings": map[string]any{
					"items":    []map[string]any{},
					"pageInfo": map[string]any{"next": nil, "total": 0},
				},
			},
		})
	})
	defer done()

	items, err := ListAll[testItem](context.Background(), c, "/app", "query { listThings }", nil, "listThings")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 items, got %d", len(items))
	}
}

func TestListAll_MissingResultKey(t *testing.T) {
	t.Parallel()

	c, done := newTestPaginationClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		testEncodeJSON(t, w, map[string]any{
			"data": map[string]any{
				"otherKey": map[string]any{},
			},
		})
	})
	defer done()

	_, err := ListAll[testItem](context.Background(), c, "/app", "query { listThings }", nil, "listThings")
	if err == nil {
		t.Fatal("expected error for missing result key")
	}
	if !strings.Contains(err.Error(), "response missing expected key") {
		t.Errorf("expected missing key error, got: %v", err)
	}
}

func TestListAll_UnmarshalError(t *testing.T) {
	t.Parallel()

	c, done := newTestPaginationClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a string instead of an object for the result key.
		_, err := fmt.Fprint(w, `{"data":{"listThings":"not an object"}}`)
		if err != nil {
			t.Fatal(err)
		}
	})
	defer done()

	_, err := ListAll[testItem](context.Background(), c, "/app", "query { listThings }", nil, "listThings")
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "decoding listThings") {
		t.Errorf("expected decoding error, got: %v", err)
	}
}

func TestListAll_GraphQLError(t *testing.T) {
	t.Parallel()

	c, done := newTestPaginationClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		testEncodeJSON(t, w, map[string]any{
			"errors": []map[string]any{{"message": "internal server error"}},
		})
	})
	defer done()

	_, err := ListAll[testItem](context.Background(), c, "/app", "query { listThings }", nil, "listThings")
	if err == nil {
		t.Fatal("expected error from GraphQL response")
	}
}

func TestListAll_BaseVarsNotMutated(t *testing.T) {
	t.Parallel()

	callCount := 0
	c, done := newTestPaginationClient(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			testEncodeJSON(t, w, map[string]any{
				"data": map[string]any{
					"listThings": map[string]any{
						"items":    []map[string]any{{"id": "a"}},
						"pageInfo": map[string]any{"next": "tok", "total": 2},
					},
				},
			})
			return
		}
		testEncodeJSON(t, w, map[string]any{
			"data": map[string]any{
				"listThings": map[string]any{
					"items":    []map[string]any{{"id": "b"}},
					"pageInfo": map[string]any{"next": nil, "total": 2},
				},
			},
		})
	})
	defer done()

	baseVars := map[string]any{"pageSize": 100}
	_, err := ListAll[testItem](context.Background(), c, "/app", "query { listThings }", baseVars, "listThings")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify baseVars was not mutated with nextToken.
	if _, ok := baseVars["nextToken"]; ok {
		t.Error("baseVars was mutated with nextToken")
	}
	raw, _ := json.Marshal(baseVars)
	if string(raw) != `{"pageSize":100}` {
		t.Errorf("baseVars mutated: %s", raw)
	}
}
