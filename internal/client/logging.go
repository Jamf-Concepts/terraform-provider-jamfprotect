package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

// Logger is an interface for logging HTTP requests and responses.
type Logger interface {
	LogRequest(ctx context.Context, method, url string, headers http.Header, body []byte)
	LogResponse(ctx context.Context, statusCode int, headers http.Header, body []byte)
}

// httpDoer is an interface that matches the Do method of http.Client, allowing for easier testing and logging.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// loggingDoer is an httpDoer that logs requests and responses using a Logger.
type loggingDoer struct {
	base   httpDoer
	logger Logger
}

// Do implements the httpDoer interface, logging the request and response.
func (d *loggingDoer) Do(req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	if d.logger != nil {
		d.logger.LogRequest(req.Context(), req.Method, req.URL.String(), redactRequestHeaders(req.Header), reqBody)
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

// redactRequestHeaders creates a redacted version of the request headers for logging, hiding sensitive information like the Authorization header.
func redactRequestHeaders(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	clone := headers.Clone()
	if clone.Get("Authorization") != "" {
		clone.Set("Authorization", "[REDACTED]")
	}
	return clone
}
