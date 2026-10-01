// Copyright 2023 OpenSSF Scorecard Authors
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
package roundtripper

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ossf/scorecard/v4/log"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	var requestCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Customize the response headers and body based on the test scenario
		//nolint:errcheck
		switch r.URL.Path {
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		case "/retry":
			requestCount++
			if requestCount == 2 {
				// Second request: Return successful response
				w.Header().Set("X-RateLimit-Remaining", "10")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Success"))
			} else {
				// First request: Return Retry-After header
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte("Rate Limit Exceeded"))
			}
		case "/success":
			w.Header().Set("X-RateLimit-Remaining", "10")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		}
	}))
	t.Cleanup(func() {
		defer ts.Close()
	})

	// Create the rateLimitTransport with the test server as the inner transport and a default logger
	transport := &rateLimitTransport{
		innerTransport: ts.Client().Transport,
		logger:         log.NewLogger(log.DefaultLevel),
		maxWait:        time.Minute,
	}

	t.Run("Successful response", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/success", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		}
	})

	t.Run("Retry-After header set", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/retry", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		}
		if requestCount != 2 {
			t.Errorf("Expected 2 requests, got %d", requestCount)
		}
	})
}

type ghResponse struct {
	retryAfter string
	remaining  string
	resource   string // defaults to "search"
	resetIn    time.Duration
	status     int
}

func (g ghResponse) write(w http.ResponseWriter) {
	if g.resource == "" {
		g.resource = "search"
	}
	w.Header().Set("X-RateLimit-Resource", g.resource)
	if g.remaining != "" {
		w.Header().Set("X-RateLimit-Remaining", g.remaining)
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(g.resetIn).Unix(), 10))
	}
	if g.retryAfter != "" {
		w.Header().Set("Retry-After", g.retryAfter)
	}
	w.WriteHeader(g.status)
}

// Replays GitHub's search limit: the 30th call returns 200 with Remaining=0, later ones 403 without Retry-After.
func TestRoundTripSearchRateLimit(t *testing.T) {
	t.Parallel()

	emptyBudget := func(resetIn time.Duration) ghResponse {
		return ghResponse{status: http.StatusForbidden, remaining: "0", resetIn: resetIn}
	}
	budgetLeft := ghResponse{status: http.StatusOK, remaining: "29", resetIn: time.Minute}

	tests := []struct {
		wantErrIs    error
		name         string
		wantErrText  string
		responses    []ghResponse // last entry repeats
		ctxTimeout   time.Duration
		maxDuration  time.Duration
		wantCalls    int32
		wantStatus   int
		wantMinWait  time.Duration
		wantErr      bool
		waitDisabled bool
	}{
		{
			name:        "budget empty, reset in 2s: waits for the reset and retries",
			responses:   []ghResponse{emptyBudget(2 * time.Second), budgetLeft},
			wantStatus:  http.StatusOK,
			wantCalls:   2,
			wantMinWait: time.Second,
			maxDuration: 5 * time.Second,
		},
		{
			name:        "budget empty again after the reset: waits again and retries",
			responses:   []ghResponse{emptyBudget(time.Second), emptyBudget(time.Second), budgetLeft},
			wantStatus:  http.StatusOK,
			wantCalls:   3,
			maxDuration: 5 * time.Second,
		},
		{
			name:        "call that uses the last slot: 200 with remaining 0 is returned as a success",
			responses:   []ghResponse{{status: http.StatusOK, remaining: "0", resetIn: 30 * time.Second}},
			wantStatus:  http.StatusOK,
			wantCalls:   1,
			maxDuration: 3 * time.Second,
		},
		{
			name: "GraphQL 200 with remaining 0 is an exhausted limit: waits and retries",
			responses: []ghResponse{
				{status: http.StatusOK, remaining: "0", resource: "graphql", resetIn: time.Second},
				budgetLeft,
			},
			wantStatus:  http.StatusOK,
			wantCalls:   2,
			maxDuration: 5 * time.Second,
		},
		{
			name: "429 with an empty budget: waits and retries",
			responses: []ghResponse{
				{status: http.StatusTooManyRequests, remaining: "0", resetIn: time.Second},
				budgetLeft,
			},
			wantStatus:  http.StatusOK,
			wantCalls:   2,
			maxDuration: 5 * time.Second,
		},
		{
			name:        "reset already passed (negative wait): retries at once",
			responses:   []ghResponse{emptyBudget(-2 * time.Second), budgetLeft},
			wantStatus:  http.StatusOK,
			wantCalls:   2,
			maxDuration: 3 * time.Second,
		},
		{
			name:        "reset beyond the wait cap: fails fast and names the exhausted budget",
			responses:   []ghResponse{emptyBudget(time.Hour)},
			wantErr:     true,
			wantErrIs:   errGitHubRateLimitExceeded,
			wantErrText: "search",
			wantCalls:   1,
			maxDuration: 3 * time.Second,
		},
		{
			name:         "waiting disabled: fails at once",
			responses:    []ghResponse{emptyBudget(2 * time.Second)},
			waitDisabled: true,
			wantErr:      true,
			wantErrIs:    errGitHubRateLimitExceeded,
			wantCalls:    1,
			maxDuration:  3 * time.Second,
		},
		{
			name:        "Retry-After on every call: gives up after the maximum number of retries",
			responses:   []ghResponse{{status: http.StatusTooManyRequests, retryAfter: "1"}},
			wantErr:     true,
			wantErrIs:   errGitHubRateLimitExceeded,
			wantCalls:   maxRetryAfterAttempts + 1,
			maxDuration: 10 * time.Second,
		},
		{
			name:        "Retry-After beyond the wait cap: fails at once",
			responses:   []ghResponse{{status: http.StatusTooManyRequests, retryAfter: "120"}},
			wantErr:     true,
			wantErrIs:   errGitHubRateLimitExceeded,
			wantCalls:   1,
			maxDuration: 3 * time.Second,
		},
		{
			name:        "context cancelled while waiting for the reset: stops waiting",
			responses:   []ghResponse{emptyBudget(30 * time.Second)},
			ctxTimeout:  300 * time.Millisecond,
			wantErr:     true,
			wantErrIs:   context.DeadlineExceeded,
			wantCalls:   1,
			maxDuration: 3 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n := int(calls.Add(1))
				tt.responses[min(n, len(tt.responses))-1].write(w)
			}))
			t.Cleanup(ts.Close)

			transport := &rateLimitTransport{
				innerTransport: ts.Client().Transport,
				logger:         log.NewLogger(log.DefaultLevel),
				maxWait:        time.Minute,
			}
			if tt.waitDisabled {
				transport.maxWait = 0
			}

			ctx := context.Background()
			if tt.ctxTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
				t.Cleanup(cancel)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/search/commits", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			type result struct {
				resp *http.Response
				err  error
			}
			done := make(chan result, 1)
			start := time.Now()
			go func() {
				resp, err := transport.RoundTrip(req) //nolint:bodyclose // closed below
				done <- result{resp, err}
			}()

			var got result
			select {
			case got = <-done:
			case <-time.After(tt.maxDuration + 2*time.Second):
				t.Fatalf("RoundTrip did not return within %s (%d calls so far)", tt.maxDuration, calls.Load())
			}
			elapsed := time.Since(start)
			if got.resp != nil {
				defer got.resp.Body.Close()
			}

			if tt.wantErr {
				if got.err == nil {
					t.Fatalf("expected an error, got status %d", got.resp.StatusCode)
				}
				if tt.wantErrIs != nil && !errors.Is(got.err, tt.wantErrIs) {
					t.Errorf("expected error wrapping %v, got: %v", tt.wantErrIs, got.err)
				}
				if tt.wantErrText != "" && !strings.Contains(got.err.Error(), tt.wantErrText) {
					t.Errorf("expected error to mention %q, got: %v", tt.wantErrText, got.err)
				}
			} else {
				if got.err != nil {
					t.Fatalf("unexpected error: %v", got.err)
				}
				if got.resp.StatusCode != tt.wantStatus {
					t.Errorf("expected status %d, got %d", tt.wantStatus, got.resp.StatusCode)
				}
			}

			if n := calls.Load(); n != tt.wantCalls {
				t.Errorf("expected %d calls to GitHub, got %d", tt.wantCalls, n)
			}
			if elapsed < tt.wantMinWait {
				t.Errorf("expected to wait at least %s for the reset, returned after %s", tt.wantMinWait, elapsed)
			}
			if elapsed > tt.maxDuration {
				t.Errorf("expected to return within %s, took %s", tt.maxDuration, elapsed)
			}
		})
	}
}

//nolint:paralleltest // t.Setenv cannot be used with parallel tests
func TestMaxRateLimitWaitFromEnv(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "unset uses the default", value: "", want: defaultMaxRateLimitWait},
		{name: "duration is used as is", value: "90s", want: 90 * time.Second},
		{name: "zero disables waiting", value: "0", want: 0},
		{name: "invalid value uses the default", value: "two minutes", want: defaultMaxRateLimitWait},
		{name: "negative value uses the default", value: "-1m", want: defaultMaxRateLimitWait},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(maxRateLimitWaitEnv, tt.value)
			if got := maxRateLimitWaitFromEnv(log.NewLogger(log.DefaultLevel)); got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

// roundTripFunc bypasses net/http, whose Transport would replay bodies itself.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRoundTripRetryResendsBody(t *testing.T) {
	t.Parallel()

	const payload = `{"query":"{ viewer { login } }"}`
	var bodies []string
	inner := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, string(body))
		rec := httptest.NewRecorder()
		if len(bodies) == 1 {
			ghResponse{status: http.StatusForbidden, remaining: "0", resetIn: -time.Second}.write(rec)
		} else {
			ghResponse{status: http.StatusOK, remaining: "10", resetIn: time.Minute}.write(rec)
		}
		return rec.Result(), nil
	})

	transport := &rateLimitTransport{
		innerTransport: inner,
		logger:         log.NewLogger(log.DefaultLevel),
		maxWait:        time.Minute,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://api.github.com/graphql",
		strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if len(bodies) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(bodies))
	}
	for i, got := range bodies {
		if got != payload {
			t.Errorf("call %d: expected body %q, got %q", i+1, payload, got)
		}
	}
}

type staticToken string

func (s staticToken) Next() (uint64, string) { return 0, string(s) }
func (staticToken) Release(uint64)           {}

// A retry through the token transport must not send the Authorization header twice (GitHub returns 401).
func TestRoundTripRetryAuthorizesOnce(t *testing.T) {
	t.Parallel()

	var authHeaders [][]string
	github := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		authHeaders = append(authHeaders, r.Header.Values("Authorization"))
		rec := httptest.NewRecorder()
		switch {
		case len(r.Header.Values("Authorization")) != 1:
			rec.WriteHeader(http.StatusUnauthorized)
		case len(authHeaders) == 1:
			ghResponse{status: http.StatusForbidden, remaining: "0", resetIn: -time.Second}.write(rec)
		default:
			ghResponse{status: http.StatusOK, remaining: "10", resetIn: time.Minute}.write(rec)
		}
		return rec.Result(), nil
	})

	transport := &rateLimitTransport{
		innerTransport: makeGitHubTransport(github, staticToken("test-token")),
		logger:         log.NewLogger(log.DefaultLevel),
		maxWait:        time.Minute,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://api.github.com/search/commits", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d (Authorization headers per call: %d)",
			http.StatusOK, resp.StatusCode, len(authHeaders[len(authHeaders)-1]))
	}
	for i, h := range authHeaders {
		if len(h) != 1 {
			t.Errorf("call %d: expected 1 Authorization header, got %d", i+1, len(h))
		}
	}
}
