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

	graphql "github.com/hasura/go-graphql-client"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/singleflight"
)

// Sentinel errors returned by the client.
var (
	ErrAuthentication = errors.New("jamfprotect: authentication failed")
	ErrGraphQL        = errors.New("jamfprotect: graphql error")
	ErrNotFound       = errors.New("jamfprotect: resource not found")
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

// Logger is an interface for logging HTTP requests and responses.
type Logger interface {
	LogRequest(ctx context.Context, method, url string, headers http.Header, body []byte)
	LogResponse(ctx context.Context, statusCode int, headers http.Header, body []byte)
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

// authenticate obtains (or refreshes) an access token. Thread-safe.
func (c *Client) authenticate(ctx context.Context) (*oauth2.Token, error) {
	if token := c.currentToken(); token != nil {
		return token, nil
	}

	value, err, _ := c.tokenGroup.Do("token", func() (any, error) {
		if token := c.currentToken(); token != nil {
			return token, nil
		}
		token, err := c.fetchToken(ctx)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.token = token
		c.mu.Unlock()
		return token, nil
	})
	if err != nil {
		return nil, err
	}
	token, ok := value.(*oauth2.Token)
	if !ok {
		return nil, fmt.Errorf("unexpected token type %T", value)
	}
	return token, nil
}

func (c *Client) currentToken() *oauth2.Token {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil && c.token.Valid() {
		return c.token
	}
	return nil
}

func (c *Client) fetchToken(ctx context.Context) (*oauth2.Token, error) {
	body, err := json.Marshal(tokenRequest{
		ClientID: c.oauthConfig.ClientID,
		Password: c.oauthConfig.ClientSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.oauthConfig.TokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	if c.logger != nil {
		c.logger.LogRequest(ctx, http.MethodPost, req.URL.String(), req.Header, body)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}
	if c.logger != nil {
		c.logger.LogResponse(ctx, resp.StatusCode, resp.Header, respBody)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request returned %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: token response missing access_token", ErrAuthentication)
	}

	if tokenResp.ExpiresIn <= 0 {
		return nil, fmt.Errorf("%w: token response missing expires_in", ErrAuthentication)
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	if time.Duration(tokenResp.ExpiresIn)*time.Second > tokenExpirySkew {
		expiry = expiry.Add(-tokenExpirySkew)
	}
	return &oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		Expiry:      expiry,
	}, nil
}

// Query executes a GraphQL query/mutation against the /app endpoint and
// decodes the result into target.
func (c *Client) Query(ctx context.Context, query string, variables map[string]any, target any) error {
	token, err := c.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthentication, err)
	}

	client := c.newGraphQLClient().WithRequestModifier(func(r *http.Request) {
		r.Header.Set("Authorization", token.AccessToken)
		r.Header.Set("User-Agent", c.userAgent)
	})

	if target == nil {
		_, err := client.ExecRaw(ctx, query, variables)
		return c.mapGraphQLError(err)
	}

	return c.mapGraphQLError(client.Exec(ctx, query, target, variables))
}

// QueryStruct executes a GraphQL query built from a struct definition.
func (c *Client) QueryStruct(ctx context.Context, query any, variables map[string]any) error {
	token, err := c.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthentication, err)
	}

	client := c.newGraphQLClient().WithRequestModifier(func(r *http.Request) {
		r.Header.Set("Authorization", token.AccessToken)
		r.Header.Set("User-Agent", c.userAgent)
	})

	return c.mapGraphQLError(client.Query(ctx, query, variables))
}

// MutateStruct executes a GraphQL mutation built from a struct definition.
func (c *Client) MutateStruct(ctx context.Context, mutation any, variables map[string]any) error {
	token, err := c.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthentication, err)
	}

	client := c.newGraphQLClient().WithRequestModifier(func(r *http.Request) {
		r.Header.Set("Authorization", token.AccessToken)
		r.Header.Set("User-Agent", c.userAgent)
	})

	return c.mapGraphQLError(client.Mutate(ctx, mutation, variables))
}

// AccessToken ensures a valid token is available and returns it.
// Tokens returned by Jamf Protect do not include a "Bearer" prefix.
func (c *Client) AccessToken(ctx context.Context) (*oauth2.Token, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthentication, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return token, nil
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

func (c *Client) newGraphQLClient() *graphql.Client {
	return graphql.NewClient(c.baseURL+"/app", c.graphqlDoer())
}

func (c *Client) graphqlDoer() graphql.Doer {
	if c.logger == nil {
		return c.httpClient
	}

	return &loggingDoer{
		base:   c.httpClient,
		logger: c.logger,
	}
}

func (c *Client) mapGraphQLError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	var gqlErrs graphql.Errors
	if !errors.As(err, &gqlErrs) {
		return err
	}

	if isRequestError(gqlErrs) {
		return err
	}

	messages := make([]string, 0, len(gqlErrs))
	isNotFound := false
	for _, e := range gqlErrs {
		msg := e.Message
		if msg == "" {
			msg = e.Error()
		}
		messages = append(messages, msg)
		lower := strings.ToLower(msg)
		if strings.Contains(lower, "not found") || strings.Contains(lower, "not_found") {
			isNotFound = true
		}
	}
	if len(messages) == 0 {
		return err
	}

	errMsg := strings.Join(messages, "; ")
	if isNotFound {
		return fmt.Errorf("%w: %w: %s", ErrNotFound, ErrGraphQL, errMsg)
	}
	return fmt.Errorf("%w: %s", ErrGraphQL, errMsg)
}

func isRequestError(errs graphql.Errors) bool {
	for _, e := range errs {
		code, ok := e.Extensions["code"].(string)
		if !ok {
			continue
		}
		switch code {
		case graphql.ErrRequestError,
			graphql.ErrJsonEncode,
			graphql.ErrJsonDecode,
			graphql.ErrGraphQLEncode,
			graphql.ErrGraphQLDecode,
			graphql.ErrGraphQLExtensionsDecode:
			return true
		default:
			continue
		}
	}
	return false
}

type loggingDoer struct {
	base   graphql.Doer
	logger Logger
}

func (d *loggingDoer) Do(req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	if d.logger != nil {
		d.logger.LogRequest(req.Context(), req.Method, req.URL.String(), req.Header, reqBody)
	}

	resp, err := d.base.Do(req)
	if err != nil {
		return resp, err
	}
	if resp != nil && resp.Body != nil {
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		if d.logger != nil {
			d.logger.LogResponse(req.Context(), resp.StatusCode, resp.Header, respBody)
		}
	}
	return resp, nil
}
