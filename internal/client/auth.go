// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const tokenExpirySkew = 60 * time.Second

// Token holds an access token and its metadata.
type Token struct {
	AccessToken string
	TokenType   string
	Expiry      time.Time
}

// Valid reports whether the token is present and not expired.
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && t.Expiry.After(time.Now())
}

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

// AccessToken ensures a valid token is available and returns it.
// Tokens returned by Jamf Protect do not include a "Bearer" prefix.
func (c *Client) AccessToken(ctx context.Context) (*Token, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthentication, err)
	}
	return token, nil
}

// authenticate obtains (or refreshes) an access token. Thread-safe.
func (c *Client) authenticate(ctx context.Context) (*Token, error) {
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
	token, ok := value.(*Token)
	if !ok {
		return nil, fmt.Errorf("unexpected token type %T", value)
	}
	return token, nil
}

// currentToken returns the current token if it's valid, or nil if it's missing or expired. Thread-safe.
func (c *Client) currentToken() *Token {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil && c.token.Valid() {
		return c.token
	}
	return nil
}

// fetchToken performs the actual HTTP request to obtain a new access token using the client credentials flow.
func (c *Client) fetchToken(ctx context.Context) (*Token, error) {
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
		c.logger.LogRequest(ctx, http.MethodPost, req.URL.String(), req.Header, redactTokenRequestBody(c.oauthConfig.ClientID))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}
	if c.logger != nil {
		c.logger.LogResponse(ctx, resp.StatusCode, resp.Header, redactTokenResponseBody(respBody))
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
	return &Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		Expiry:      expiry,
	}, nil
}

// redactTokenRequestBody creates a redacted version of the token request body for logging, hiding the password.
func redactTokenRequestBody(clientID string) []byte {
	data, err := json.Marshal(map[string]string{
		"client_id": clientID,
		"password":  "[REDACTED]",
	})
	if err != nil {
		return []byte(`{"password":"[REDACTED]"}`)
	}
	return data
}

// redactTokenResponseBody creates a redacted version of the token response body for logging, hiding the access token.
func redactTokenResponseBody(body []byte) []byte {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	if _, ok := payload["access_token"]; ok {
		payload["access_token"] = "[REDACTED]"
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return data
}
