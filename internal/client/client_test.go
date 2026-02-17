package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testEncodeJSON is a helper to handle JSON encoding in tests.
func testEncodeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("failed to encode JSON: %v", err)
	}
}

// testWrite is a helper to handle writes in tests.
func testWrite(t *testing.T, w http.ResponseWriter, data []byte) {
	t.Helper()
	if _, err := w.Write(data); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
}

// testDecodeJSON is a helper to handle JSON decoding in tests.
func testDecodeJSON(t *testing.T, r *http.Request, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
}

type loggedRequest struct {
	method  string
	url     string
	headers http.Header
	body    []byte
}

type loggedResponse struct {
	status  int
	headers http.Header
	body    []byte
}

type testLogger struct {
	mu        sync.Mutex
	requests  []loggedRequest
	responses []loggedResponse
}

func (l *testLogger) LogRequest(_ context.Context, method, url string, headers http.Header, body []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests = append(l.requests, loggedRequest{
		method:  method,
		url:     url,
		headers: headers.Clone(),
		body:    append([]byte(nil), body...),
	})
}

func (l *testLogger) LogResponse(_ context.Context, statusCode int, headers http.Header, body []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.responses = append(l.responses, loggedResponse{
		status:  statusCode,
		headers: headers.Clone(),
		body:    append([]byte(nil), body...),
	})
}

func (l *testLogger) requestAt(index int) loggedRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.requests[index]
}

func (l *testLogger) responseAt(index int) loggedResponse {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.responses[index]
}

func (l *testLogger) requestCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.requests)
}

func (l *testLogger) responseCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.responses)
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	c := NewClient("https://example.protect.jamfcloud.com/", "client-id", "secret")

	if c.baseURL != "https://example.protect.jamfcloud.com" {
		t.Errorf("expected trailing slash trimmed, got %q", c.baseURL)
	}
	if c.oauthConfig.ClientID != "client-id" {
		t.Errorf("expected clientID %q, got %q", "client-id", c.oauthConfig.ClientID)
	}
	if c.oauthConfig.ClientSecret != "secret" {
		t.Errorf("expected clientSecret %q, got %q", "secret", c.oauthConfig.ClientSecret)
	}
	if c.oauthConfig.TokenURL != "https://example.protect.jamfcloud.com/token" {
		t.Errorf("expected token URL %q, got %q", "https://example.protect.jamfcloud.com/token", c.oauthConfig.TokenURL)
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
		testEncodeJSON(t, w, map[string]any{"access_token": "test-token", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "test-token" {
			t.Errorf("expected Authorization %q, got %q", "test-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		testEncodeJSON(t, w, map[string]any{
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
	err := client.DoGraphQL(context.Background(), "/app", "query { getAnalytic { uuid name } }", nil, &result)
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
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{
			"errors": []map[string]any{
				{"message": "field not found"},
				{"message": "type mismatch"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	err := client.DoGraphQL(context.Background(), "/app", "query { bad }", nil, nil)

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
		testWrite(t, w, []byte(`{"error": "invalid_client"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "bad", "bad")
	err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil)

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
		testEncodeJSON(t, w, map[string]any{"access_token": "cached-tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")

	// Make multiple queries — token should be fetched only once.
	for range 3 {
		if err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil); err != nil {
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
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"data": map[string]any{"deleteAnalytic": map[string]any{"uuid": "x"}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	// nil target should not panic (used for mutations like delete).
	if err := client.DoGraphQL(context.Background(), "/app", "mutation { deleteAnalytic }", nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClientWithVersion(t *testing.T) {
	t.Parallel()

	c := NewClientWithVersion("https://example.protect.jamfcloud.com/", "client-id", "secret", "1.2.3")

	if c.baseURL != "https://example.protect.jamfcloud.com" {
		t.Errorf("expected trailing slash trimmed, got %q", c.baseURL)
	}
	if c.oauthConfig.ClientID != "client-id" {
		t.Errorf("expected clientID %q, got %q", "client-id", c.oauthConfig.ClientID)
	}
	if c.oauthConfig.ClientSecret != "secret" {
		t.Errorf("expected clientSecret %q, got %q", "secret", c.oauthConfig.ClientSecret)
	}
	if c.oauthConfig.TokenURL != "https://example.protect.jamfcloud.com/token" {
		t.Errorf("expected token URL %q, got %q", "https://example.protect.jamfcloud.com/token", c.oauthConfig.TokenURL)
	}
	if c.userAgent != "terraform-provider-jamfprotect/1.2.3" {
		t.Errorf("expected userAgent %q, got %q", "terraform-provider-jamfprotect/1.2.3", c.userAgent)
	}
}

func TestClient_Query_UserAgentHeader(t *testing.T) {
	t.Parallel()

	var capturedUserAgent string
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "test-token", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		capturedUserAgent = r.Header.Get("User-Agent")
		testEncodeJSON(t, w, map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClientWithVersion(srv.URL, "cid", "csecret", "1.0.0")

	err := client.DoGraphQL(context.Background(), "/app", "query { test }", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedUA := "terraform-provider-jamfprotect/1.0.0"
	if capturedUserAgent != expectedUA {
		t.Errorf("expected User-Agent %q, got %q", expectedUA, capturedUserAgent)
	}
}

func TestClient_Query_ErrNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		errorMessage   string
		extensions     map[string]any
		expectNotFound bool
	}{
		{
			name:           "not found lowercase",
			errorMessage:   "resource not found",
			expectNotFound: true,
		},
		{
			name:           "not found uppercase",
			errorMessage:   "Resource Not Found",
			expectNotFound: true,
		},
		{
			name:           "not_found with underscore",
			errorMessage:   "item not_found",
			expectNotFound: true,
		},
		{
			name:           "extensions not found",
			errorMessage:   "internal server error",
			extensions:     map[string]any{"code": "NOT_FOUND"},
			expectNotFound: false,
		},
		{
			name:           "other error",
			errorMessage:   "internal server error",
			expectNotFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mux := http.NewServeMux()
			mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
				testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
			})
			mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
				errPayload := map[string]any{"message": tc.errorMessage}
				if tc.extensions != nil {
					errPayload["extensions"] = tc.extensions
				}
				testEncodeJSON(t, w, map[string]any{
					"errors": []map[string]any{errPayload},
				})
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			client := NewClient(srv.URL, "cid", "csecret")
			err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if tc.expectNotFound {
				if !errors.Is(err, ErrNotFound) {
					t.Errorf("expected ErrNotFound, got %v", err)
				}
				if !errors.Is(err, ErrGraphQL) {
					t.Errorf("expected ErrGraphQL to also be wrapped, got %v", err)
				}
			} else {
				if errors.Is(err, ErrNotFound) {
					t.Errorf("did not expect ErrNotFound, got %v", err)
				}
				if !errors.Is(err, ErrGraphQL) {
					t.Errorf("expected ErrGraphQL, got %v", err)
				}
			}
		})
	}
}

func TestClient_Logger_RedactsTokenRequest(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok-secret", "expires_in": 3600})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	logger := &testLogger{}
	client.SetLogger(logger)

	if _, err := client.AccessToken(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if logger.requestCount() == 0 {
		t.Fatal("expected token request to be logged")
	}
	req := logger.requestAt(0)
	if strings.Contains(string(req.body), "csecret") {
		t.Fatalf("expected token request body to be redacted")
	}
	if !strings.Contains(string(req.body), "[REDACTED]") {
		t.Fatalf("expected redacted marker in token request body")
	}

	if logger.responseCount() == 0 {
		t.Fatal("expected token response to be logged")
	}
	resp := logger.responseAt(0)
	if strings.Contains(string(resp.body), "tok-secret") {
		t.Fatalf("expected token response body to be redacted")
	}
}

func TestClient_Logger_RedactsAuthorizationHeader(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	logger := &testLogger{}
	client.SetLogger(logger)

	if err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if logger.requestCount() < 2 {
		t.Fatalf("expected token and graphql requests to be logged")
	}
	graphQLReq := logger.requestAt(1)
	if got := graphQLReq.headers.Get("Authorization"); got != "[REDACTED]" {
		t.Fatalf("expected Authorization to be redacted, got %q", got)
	}
}

func TestClient_Query_ContextCancellation(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.DoGraphQL(ctx, "/app", "query { x }", nil, nil)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestClient_Query_HTTPError(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		testWrite(t, w, []byte("internal server error"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil)

	if err == nil {
		t.Fatal("expected error from HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention status 500, got: %v", err)
	}
}

func TestClient_Query_MalformedJSON(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		testWrite(t, w, []byte("{invalid json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil)

	if err == nil {
		t.Fatal("expected error from malformed JSON, got nil")
	}
}

func TestClient_Authenticate_EmptyToken(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "", "expires_in": 3600})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")
	err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil)

	if err == nil {
		t.Fatal("expected error from empty token, got nil")
	}
	if !errors.Is(err, ErrAuthentication) {
		t.Errorf("expected ErrAuthentication, got %v", err)
	}
}

func TestClient_AccessToken_ExpiresIn(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{
			"access_token": "tok",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")

	start := time.Now()
	token, err := client.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	end := time.Now()

	minExpected := start.Add(59 * time.Minute)
	maxExpected := end.Add(60 * time.Minute)
	if token.Expiry.Before(minExpected) || token.Expiry.After(maxExpected) {
		t.Fatalf("unexpected expiry time: %s (expected between %s and %s)", token.Expiry, minExpected, maxExpected)
	}
}

func TestClient_Query_WithVariables(t *testing.T) {
	t.Parallel()

	var receivedQuery string
	var receivedVars map[string]any

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		testDecodeJSON(t, r, &req)
		receivedQuery = req.Query
		receivedVars = req.Variables

		testEncodeJSON(t, w, map[string]any{"data": map[string]any{"result": "ok"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")

	query := "query GetItem($id: ID!) { getItem(id: $id) { name } }"
	vars := map[string]any{"id": "123"}

	err := client.DoGraphQL(context.Background(), "/app", query, vars, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedQuery != query {
		t.Errorf("query not passed correctly")
	}
	if receivedVars["id"] != "123" {
		t.Errorf("variables not passed correctly")
	}
}

func TestClient_Query_NullData(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"data": nil})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")

	var result struct {
		Item *string `json:"item"`
	}
	err := client.DoGraphQL(context.Background(), "/app", "query { item }", nil, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
