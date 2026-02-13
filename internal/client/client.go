// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by the client.
var (
	ErrAuthentication = errors.New("jamfprotect: authentication failed")
	ErrGraphQL        = errors.New("jamfprotect: graphql error")
	ErrNotFound       = errors.New("jamfprotect: resource not found")
)

// Client communicates with the Jamf Protect GraphQL API.
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	userAgent    string
	httpClient   *http.Client
	mu           sync.Mutex
	accessToken  string
	tokenExpiry  time.Time
}

const tokenExpirySkew = 60 * time.Second

// tokenRequest is the payload sent to the /token endpoint.
type tokenRequest struct {
	ClientID string `json:"client_id"`
	Password string `json:"password"`
}

// tokenResponse is the response from the /token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
}

// graphqlRequest is the JSON payload for a GraphQL request.
type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

// graphqlResponse is the raw GraphQL response envelope.
type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []GraphQLError  `json:"errors,omitempty"`
}

// GraphQLError represents an error returned by the GraphQL endpoint.
type GraphQLError struct {
	Message string `json:"message"`
	Path    []any  `json:"path,omitempty"`
}

// NewClient creates a new Jamf Protect GraphQL client.
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return NewClientWithVersion(baseURL, clientID, clientSecret, "dev")
}

// NewClientWithVersion creates a new Jamf Protect GraphQL client with a custom version string.
func NewClientWithVersion(baseURL, clientID, clientSecret, version string) *Client {
	userAgent := fmt.Sprintf("terraform-provider-jamfprotect/%s", version)
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		userAgent:    userAgent,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (e GraphQLError) Error() string {
	return e.Message
}

// authenticate obtains (or refreshes) an access token. Thread-safe.
func (c *Client) authenticate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}

	body, err := json.Marshal(tokenRequest{
		ClientID: c.clientID,
		Password: c.clientSecret,
	})
	if err != nil {
		return fmt.Errorf("marshalling token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/token", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request returned %d: %s", resp.StatusCode, string(b))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("decoding token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return fmt.Errorf("%w: token response missing access_token", ErrAuthentication)
	}

	c.accessToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn <= 0 {
		return fmt.Errorf("%w: token response missing expires_in", ErrAuthentication)
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	if time.Duration(tokenResp.ExpiresIn)*time.Second > tokenExpirySkew {
		expiry = expiry.Add(-tokenExpirySkew)
	}
	c.tokenExpiry = expiry
	return nil
}

// Query executes a GraphQL query/mutation against the /app endpoint and
// decodes the result into target.
func (c *Client) Query(ctx context.Context, query string, variables map[string]any, target any) error {
	if err := c.authenticate(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthentication, err)
	}

	body, err := json.Marshal(graphqlRequest{
		Query:     query,
		Variables: variables,
	})
	if err != nil {
		return fmt.Errorf("marshalling query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/app", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.accessToken)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("graphql request returned %d: %s", resp.StatusCode, string(b))
	}

	var gqlResp graphqlResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		messages := make([]string, len(gqlResp.Errors))
		isNotFound := false
		for i, e := range gqlResp.Errors {
			messages[i] = e.Message
			msg := strings.ToLower(e.Message)
			if strings.Contains(msg, "not found") || strings.Contains(msg, "not_found") {
				isNotFound = true
			}
		}
		errMsg := strings.Join(messages, "; ")
		if isNotFound {
			return fmt.Errorf("%w: %w: %s", ErrNotFound, ErrGraphQL, errMsg)
		}
		return fmt.Errorf("%w: %s", ErrGraphQL, errMsg)
	}

	if target != nil && gqlResp.Data != nil {
		if err := json.Unmarshal(gqlResp.Data, target); err != nil {
			return fmt.Errorf("unmarshalling data: %w", err)
		}
	}

	return nil
}

// AccessToken ensures a valid token is available and returns it with its expiry time.
// Tokens returned by Jamf Protect do not include a "Bearer" prefix.
func (c *Client) AccessToken(ctx context.Context) (string, time.Time, error) {
	if err := c.authenticate(ctx); err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %w", ErrAuthentication, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accessToken, c.tokenExpiry, nil
}
