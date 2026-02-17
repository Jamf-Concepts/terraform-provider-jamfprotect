// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/singleflight"
)

// Client communicates with the Jamf Protect GraphQL API.
type Client struct {
	baseURL     string
	userAgent   string
	httpClient  *http.Client
	logger      Logger
	oauthConfig clientcredentials.Config
	mu          sync.Mutex
	token       *oauth2.Token
	tokenGroup  singleflight.Group
}

// NewClient creates a new Jamf Protect GraphQL client.
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return NewClientWithVersion(baseURL, clientID, clientSecret, "dev")
}

// NewClientWithVersion creates a new Jamf Protect GraphQL client with a custom version string.
func NewClientWithVersion(baseURL, clientID, clientSecret, version string, opts ...Option) *Client {
	userAgent := fmt.Sprintf("terraform-provider-jamfprotect/%s", version)
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		userAgent:  userAgent,
		httpClient: httpClient,
		oauthConfig: clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     strings.TrimRight(baseURL, "/") + "/token",
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SetLogger sets the logger for the client.
func (c *Client) SetLogger(logger Logger) {
	c.logger = logger
}

// DoGraphQL executes a raw GraphQL query/mutation against a custom endpoint path.
// Use "/app" for the main API and "/graphql" for the limited schema endpoint.
func (c *Client) DoGraphQL(ctx context.Context, path, query string, variables map[string]any, target any) error {
	if path == "" {
		return fmt.Errorf("graphql endpoint path is required")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	token, err := c.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthentication, err)
	}

	payload, err := json.Marshal(graphQLRequest{
		Query:     query,
		Variables: variables,
	})
	if err != nil {
		return fmt.Errorf("encoding graphql request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating graphql request: %w", err)
	}
	req.Header.Set("Authorization", token.AccessToken)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/json")

	doer := c.httpDoer()
	resp, err := doer.Do(req)
	if err != nil {
		return fmt.Errorf("executing graphql request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading graphql response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("graphql request returned %d: %s", resp.StatusCode, string(respBody))
	}

	var gqlResp graphQLResponse
	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		return fmt.Errorf("decoding graphql response: %w", err)
	}
	if err := mapGraphQLErrors(gqlResp.Errors); err != nil {
		return err
	}

	if target == nil || len(gqlResp.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(gqlResp.Data, target); err != nil {
		return fmt.Errorf("decoding graphql data: %w", err)
	}
	return nil
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client used by the API client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// httpDoer returns an httpDoer that wraps the client's HTTP client with logging if a logger is set, or the raw HTTP client otherwise.
func (c *Client) httpDoer() httpDoer {
	if c.logger == nil {
		return c.httpClient
	}

	return &loggingDoer{
		base:   c.httpClient,
		logger: c.logger,
	}
}
