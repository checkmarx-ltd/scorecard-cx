// Copyright 2026 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clients

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// cannedTransport answers every request with the same response.
type cannedTransport struct {
	contentType string
	body        string
	retryAfter  string
	status      int
}

func (c cannedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.status,
		Status:     http.StatusText(c.status),
		Header:     http.Header{"Content-Type": []string{c.contentType}},
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Request:    req,
	}, nil
}

// sequenceTransport answers with one canned response per request, repeating the last one,
// and records each request.
type sequenceTransport struct {
	responses []cannedTransport
	requests  []*http.Request
	mu        sync.Mutex
}

func (s *sequenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	next := s.responses[min(len(s.requests), len(s.responses))-1]
	resp, err := next.RoundTrip(req)
	if retryAfter := next.retryAfter; retryAfter != "" {
		resp.Header.Set("Retry-After", retryAfter)
	}
	return resp, err
}

func (s *sequenceTransport) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

const badgeJSON = `[{"badge_level":"passing"}]`

func TestGetBadgeLevelRetries(t *testing.T) {
	t.Parallel()
	htmlPage := cannedTransport{status: http.StatusOK, contentType: "text/html; charset=utf-8", body: "<html>maintenance</html>"}
	badge := cannedTransport{status: http.StatusOK, contentType: "application/json; charset=utf-8", body: badgeJSON}
	tests := []struct {
		name      string
		responses []cannedTransport
		wantCalls int
		minWait   time.Duration
	}{
		{
			name:      "server error then badge",
			responses: []cannedTransport{{status: http.StatusServiceUnavailable, contentType: "text/html", body: "<html>down</html>"}, badge},
			wantCalls: 2,
		},
		{
			name:      "HTML page then badge",
			responses: []cannedTransport{htmlPage, badge},
			wantCalls: 2,
		},
		{
			name: "rate limited with Retry-After then badge",
			responses: []cannedTransport{
				{status: http.StatusTooManyRequests, contentType: "text/plain", body: "slow down", retryAfter: "2"},
				badge,
			},
			wantCalls: 2,
			minWait:   2 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			transport := &sequenceTransport{responses: tt.responses}
			client := &httpClientCIIBestPractices{transport: transport, maxWait: 10 * time.Second}

			start := time.Now()
			got, err := client.GetBadgeLevel(context.Background(), "github.com/org/repo")
			if err != nil {
				t.Fatalf("GetBadgeLevel() error = %v", err)
			}
			if got != Passing {
				t.Errorf("GetBadgeLevel() = %v, want %v", got, Passing)
			}
			if calls := transport.calls(); calls != tt.wantCalls {
				t.Errorf("GetBadgeLevel() made %d requests, want %d", calls, tt.wantCalls)
			}
			if waited := time.Since(start); waited < tt.minWait {
				t.Errorf("GetBadgeLevel() retried after %s, want at least the Retry-After of %s", waited, tt.minWait)
			}
		})
	}
}

func TestGetBadgeLevelEscapesRepoURL(t *testing.T) {
	t.Parallel()
	transport := &sequenceTransport{responses: []cannedTransport{
		{status: http.StatusOK, contentType: "application/json", body: badgeJSON},
	}}
	client := &httpClientCIIBestPractices{transport: transport}

	if _, err := client.GetBadgeLevel(context.Background(), "github.com/org/repo"); err != nil {
		t.Fatalf("GetBadgeLevel() error = %v", err)
	}
	// The escaped form is what bestpractices.dev redirects an unescaped query to.
	const wantQuery = "url=https%3A%2F%2Fgithub.com%2Forg%2Frepo"
	if got := transport.requests[0].URL.RawQuery; got != wantQuery {
		t.Errorf("request query = %q, want %q", got, wantQuery)
	}
}

func TestGetBadgeLevelStopsWaitingWhenContextEnds(t *testing.T) {
	t.Parallel()
	transport := &sequenceTransport{responses: []cannedTransport{
		{status: http.StatusServiceUnavailable, contentType: "text/html", body: "<html>down</html>"},
	}}
	client := &httpClientCIIBestPractices{transport: transport, maxWait: 10 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.GetBadgeLevel(ctx, "github.com/org/repo")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetBadgeLevel() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("GetBadgeLevel() returned after %s, want it to stop when the context ends", waited)
	}
}

// TestGetBadgeLevel covers single replies with retries disabled, which is also what the
// caller sees once the retry budget runs out.
func TestGetBadgeLevel(t *testing.T) {
	t.Parallel()
	const htmlErrorPage = "<!DOCTYPE html>\n<html><head><title>Application Error</title></head><body>An error occurred.</body></html>"
	tests := []struct {
		name        string
		contentType string
		body        string
		wantErrText []string
		status      int
		want        BadgeLevel
		wantErr     bool
	}{
		{
			name:        "badge found",
			status:      http.StatusOK,
			contentType: "application/json; charset=utf-8",
			body:        `[{"badge_level":"passing"}]`,
			want:        Passing,
		},
		{
			name:        "no badge",
			status:      http.StatusOK,
			contentType: "application/json; charset=utf-8",
			body:        `[]`,
			want:        NotFound,
		},
		{
			name:        "HTML error page with a server error status",
			status:      http.StatusServiceUnavailable,
			contentType: "text/html; charset=utf-8",
			body:        htmlErrorPage,
			want:        Unknown,
			wantErr:     true,
			wantErrText: []string{"HTTP 503", "text/html; charset=utf-8", "<title>Application Error</title>"},
		},
		{
			name:        "HTML page with a success status",
			status:      http.StatusOK,
			contentType: "text/html; charset=utf-8",
			body:        htmlErrorPage,
			want:        Unknown,
			wantErr:     true,
			wantErrText: []string{"HTTP 200", "text/html; charset=utf-8", "<title>Application Error</title>"},
		},
		{
			name:        "rate limited",
			status:      http.StatusTooManyRequests,
			contentType: "text/plain; charset=utf-8",
			body:        "Retry later",
			want:        Unknown,
			wantErr:     true,
			wantErrText: []string{"HTTP 429", "Retry later"},
		},
		{
			name:        "JSON body with an error status is not read as badge data",
			status:      http.StatusNotFound,
			contentType: "application/json; charset=utf-8",
			body:        `[{"badge_level":"passing"}]`,
			want:        Unknown,
			wantErr:     true,
			wantErrText: []string{"HTTP 404", "application/json; charset=utf-8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := &httpClientCIIBestPractices{
				transport: cannedTransport{status: tt.status, contentType: tt.contentType, body: tt.body},
			}

			got, err := client.GetBadgeLevel(context.Background(), "github.com/org/repo")
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetBadgeLevel() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetBadgeLevel() = %v, want %v", got, tt.want)
			}
			for _, text := range tt.wantErrText {
				if !strings.Contains(err.Error(), text) {
					t.Errorf("GetBadgeLevel() error = %q, want it to contain %q", err, text)
				}
			}
		})
	}
}

func TestDefaultCIIBestPracticesClientMaxWait(t *testing.T) {
	t.Setenv(ciiMaxWaitEnv, "45s")
	client, ok := DefaultCIIBestPracticesClient().(*httpClientCIIBestPractices)
	if !ok {
		t.Fatalf("DefaultCIIBestPracticesClient() = %T, want *httpClientCIIBestPractices", DefaultCIIBestPracticesClient())
	}
	if client.maxWait != 45*time.Second {
		t.Errorf("maxWait = %s, want 45s from %s", client.maxWait, ciiMaxWaitEnv)
	}
}
