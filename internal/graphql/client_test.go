// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package graphql

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	c := NewClient("https://example.protect.jamfcloud.com/", "client-id", "secret")

	if c.baseURL != "https://example.protect.jamfcloud.com" {
		t.Errorf("expected trailing slash trimmed, got %q", c.baseURL)
	}
	if c.clientID != "client-id" {
		t.Errorf("expected clientID %q, got %q", "client-id", c.clientID)
	}
	if c.clientSecret != "secret" {
		t.Errorf("expected clientSecret %q, got %q", "secret", c.clientSecret)
	}
}

func TestClient_Query_Success(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"access_token": "test-token"})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "test-token" {
			t.Errorf("expected Authorization %q, got %q", "test-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"getAnalytic": map[string]any{
					"uuid": "abc-123",
					"name": "Test Analytic",
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")

	var result struct {
		GetAnalytic struct {
			UUID string `json:"uuid"`
			Name string `json:"name"`
		} `json:"getAnalytic"`
	}
	err := client.Query(context.Background(), "query { getAnalytic { uuid name } }", nil, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.GetAnalytic.UUID != "abc-123" {
		t.Errorf("expected UUID %q, got %q", "abc-123", result.GetAnalytic.UUID)
	}
	if result.GetAnalytic.Name != "Test Analytic" {
		t.Errorf("expected Name %q, got %q", "Test Analytic", result.GetAnalytic.Name)
	}
}

func TestClient_Query_GraphQLErrors(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]any{
				{"message": "field not found"},
				{"message": "type mismatch"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	err := client.Query(context.Background(), "query { bad }", nil, nil)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrGraphQL) {
		t.Errorf("expected ErrGraphQL, got %v", err)
	}
}

func TestClient_Query_AuthFailure(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid_client"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "bad", "bad")
	err := client.Query(context.Background(), "query { x }", nil, nil)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrAuthentication) {
		t.Errorf("expected ErrAuthentication, got %v", err)
	}
}

func TestClient_TokenCaching(t *testing.T) {
	t.Parallel()

	var tokenCalls int
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		tokenCalls++
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"access_token": "cached-tok"})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")

	// Make multiple queries — token should be fetched only once.
	for range 3 {
		if err := client.Query(context.Background(), "query { x }", nil, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if tokenCalls != 1 {
		t.Errorf("expected 1 token call, got %d", tokenCalls)
	}
}

func TestClient_Query_NilTarget(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"deleteAnalytic": map[string]any{"uuid": "x"}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	// nil target should not panic (used for mutations like delete).
	if err := client.Query(context.Background(), "mutation { deleteAnalytic }", nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGraphQLError_Error(t *testing.T) {
	t.Parallel()

	e := GraphQLError{Message: "something went wrong"}
	if e.Error() != "something went wrong" {
		t.Errorf("unexpected error string: %q", e.Error())
	}
}
