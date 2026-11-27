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

package httpretry

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

var errNetwork = errors.New("connection reset")

// step is one scripted outcome of an attempt.
type step struct {
	err        error
	retryAfter string
	status     int
	delay      time.Duration // time the attempt takes before it answers
	hang       bool          // block until the attempt's context ends
}

// scriptedBase plays the steps in order, repeating the last one, and tracks every body.
type scriptedBase struct {
	steps         []step
	bodies        []*trackedBody
	requestBodies []string
	mu            sync.Mutex
	calls         int
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

func (s *scriptedBase) RoundTrip(req *http.Request) (*http.Response, error) {
	sent := ""
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		sent = string(b)
	}
	s.mu.Lock()
	next := s.steps[min(s.calls, len(s.steps)-1)]
	s.calls++
	s.requestBodies = append(s.requestBodies, sent)
	s.mu.Unlock()

	if next.hang {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	if next.delay > 0 {
		time.Sleep(next.delay)
	}
	if next.err != nil {
		return nil, next.err
	}
	body := &trackedBody{Reader: strings.NewReader("body")}
	s.mu.Lock()
	s.bodies = append(s.bodies, body)
	s.mu.Unlock()
	resp := &http.Response{StatusCode: next.status, Header: http.Header{}, Body: body, Request: req}
	if next.retryAfter != "" {
		resp.Header.Set("Retry-After", next.retryAfter)
	}
	return resp, nil
}

// newTestTransport returns a Transport without jitter whose waits are recorded instead of slept.
func newTestTransport(base *scriptedBase, maxWait time.Duration) (*Transport, *[]time.Duration) {
	waits := &[]time.Duration{}
	transport := New(base, maxWait, nil)
	transport.maxJitter = 0
	transport.wait = func(ctx context.Context, d time.Duration) error {
		*waits = append(*waits, d)
		return ctx.Err()
	}
	return transport, waits
}

func get(t *testing.T, transport http.RoundTripper, ctx context.Context) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	return transport.RoundTrip(req)
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		steps      []step
		maxWait    time.Duration
		wantStatus int
		wantCalls  int
		wantWaits  int
		wantErr    bool
	}{
		{
			name:       "success is not retried",
			steps:      []step{{status: http.StatusOK}},
			maxWait:    time.Minute,
			wantStatus: http.StatusOK,
			wantCalls:  1,
		},
		{
			name:       "client error is not retried",
			steps:      []step{{status: http.StatusNotFound}},
			maxWait:    time.Minute,
			wantStatus: http.StatusNotFound,
			wantCalls:  1,
		},
		{
			name:       "server error then success",
			steps:      []step{{status: http.StatusBadGateway}, {status: http.StatusServiceUnavailable}, {status: http.StatusOK}},
			maxWait:    time.Minute,
			wantStatus: http.StatusOK,
			wantCalls:  3,
			wantWaits:  2,
		},
		{
			name:       "network error then success",
			steps:      []step{{err: errNetwork}, {status: http.StatusOK}},
			maxWait:    time.Minute,
			wantStatus: http.StatusOK,
			wantCalls:  2,
			wantWaits:  1,
		},
		{
			name:       "zero max wait disables retries",
			steps:      []step{{status: http.StatusServiceUnavailable}, {status: http.StatusOK}},
			maxWait:    0,
			wantStatus: http.StatusServiceUnavailable,
			wantCalls:  1,
		},
		{
			name:       "budget exhausted returns the last reply",
			steps:      []step{{status: http.StatusTooManyRequests}},
			maxWait:    6 * time.Second,
			wantStatus: http.StatusTooManyRequests,
			// waits of 1s and 2s fit in 6s, the next one of 4s does not
			wantCalls: 3,
			wantWaits: 2,
		},
		{
			name:       "Retry-After beyond the budget is not waited for",
			steps:      []step{{status: http.StatusTooManyRequests, retryAfter: "120"}},
			maxWait:    time.Minute,
			wantStatus: http.StatusTooManyRequests,
			wantCalls:  1,
		},
		{
			name:      "network error until the budget runs out",
			steps:     []step{{err: errNetwork}},
			maxWait:   0,
			wantCalls: 1,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := &scriptedBase{steps: tt.steps}
			transport, waits := newTestTransport(base, tt.maxWait)

			resp, err := get(t, transport, context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("RoundTrip() error = %v, wantErr %v", err, tt.wantErr)
			}
			if resp != nil && resp.StatusCode != tt.wantStatus {
				t.Errorf("RoundTrip() status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if base.calls != tt.wantCalls {
				t.Errorf("RoundTrip() made %d attempts, want %d", base.calls, tt.wantCalls)
			}
			if tt.wantWaits >= 0 && len(*waits) != tt.wantWaits {
				t.Errorf("RoundTrip() waited %d times, want %d", len(*waits), tt.wantWaits)
			}
			// Every discarded reply is closed; the returned one is left for the caller.
			for i, body := range base.bodies {
				isReturned := resp != nil && i == len(base.bodies)-1
				if body.closed == isReturned {
					t.Errorf("body %d closed = %t, want %t", i, body.closed, !isReturned)
				}
			}
		})
	}
}

func TestRoundTripFollowsRetryAfter(t *testing.T) {
	t.Parallel()
	base := &scriptedBase{steps: []step{{status: http.StatusTooManyRequests, retryAfter: "7"}, {status: http.StatusOK}}}
	transport, waits := newTestTransport(base, time.Minute)

	if _, err := get(t, transport, context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*waits) != 1 || (*waits)[0] != 7*time.Second {
		t.Errorf("waits = %v, want one wait of 7s", *waits)
	}
}

func TestRoundTripAddsJitter(t *testing.T) {
	t.Parallel()
	for range 20 {
		base := &scriptedBase{steps: []step{{status: http.StatusTooManyRequests, retryAfter: "7"}, {status: http.StatusOK}}}
		transport, waits := newTestTransport(base, time.Minute)
		transport.maxJitter = retryJitter

		if _, err := get(t, transport, context.Background()); err != nil {
			t.Fatal(err)
		}
		if wait := (*waits)[0]; wait < 7*time.Second || wait >= 7*time.Second+retryJitter {
			t.Fatalf("wait = %s, want 7s plus under %s of jitter", wait, retryJitter)
		}
	}
}

func TestRoundTripRetriesAnAttemptThatTimesOut(t *testing.T) {
	t.Parallel()
	base := &scriptedBase{steps: []step{{hang: true}, {status: http.StatusOK}}}
	transport, _ := newTestTransport(base, time.Minute)
	transport.attemptTimeout = 50 * time.Millisecond

	resp, err := get(t, transport, context.Background())
	if err != nil {
		t.Fatalf("RoundTrip() error = %v, want the timed out attempt to be retried", err)
	}
	if resp.StatusCode != http.StatusOK || base.calls != 2 {
		t.Errorf("RoundTrip() = %d after %d attempts, want 200 after 2", resp.StatusCode, base.calls)
	}
}

func TestRoundTripCountsAttemptTimeInTheBudget(t *testing.T) {
	t.Parallel()
	// Each attempt takes 100ms and asks to retry at once. The waits are zero, so only the time
	// spent in attempts can end the retries: about 4 attempts fit a 350ms budget.
	base := &scriptedBase{steps: []step{{status: http.StatusTooManyRequests, retryAfter: "0", delay: 100 * time.Millisecond}}}
	transport, _ := newTestTransport(base, 350*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := get(t, transport, ctx)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v, want the last 429 once the budget is spent", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("RoundTrip() status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
	if base.calls < 3 || base.calls > 5 {
		t.Errorf("RoundTrip() made %d attempts, want about 4 within 350ms", base.calls)
	}
}

func TestRoundTripCapsRetryAfterAttempts(t *testing.T) {
	t.Parallel()
	// A server that always asks to retry at once must not be hammered for the whole budget.
	base := &scriptedBase{steps: []step{{status: http.StatusTooManyRequests, retryAfter: "0"}}}
	transport, _ := newTestTransport(base, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := get(t, transport, ctx)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v, want the last 429 after the Retry-After attempts", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("RoundTrip() status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
	if want := 1 + maxRetryAfterAttempts; base.calls != want {
		t.Errorf("RoundTrip() made %d attempts, want %d", base.calls, want)
	}
}

func TestRoundTripReplaysTheBody(t *testing.T) {
	t.Parallel()
	base := &scriptedBase{steps: []step{{status: http.StatusServiceUnavailable}, {status: http.StatusOK}}}
	transport, _ := newTestTransport(base, time.Minute)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/graphql",
		strings.NewReader(`{"query":"q"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if len(base.requestBodies) != 2 {
		t.Fatalf("got %d attempts, want 2", len(base.requestBodies))
	}
	for i, body := range base.requestBodies {
		if body != `{"query":"q"}` {
			t.Errorf("attempt %d sent body %q, want the original body", i, body)
		}
	}
}

func TestRoundTripStopsWhenContextEnds(t *testing.T) {
	t.Parallel()
	base := &scriptedBase{steps: []step{{status: http.StatusServiceUnavailable}}}
	transport := New(base, time.Minute, nil) // real wait

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := get(t, transport, ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RoundTrip() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("RoundTrip() returned after %s, want it to stop when the context ends", elapsed)
	}
}

func TestBackoff(t *testing.T) {
	t.Parallel()
	for attempt, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second} {
		if got := backoff(attempt); got != want {
			t.Errorf("backoff(%d) = %s, want %s", attempt, got, want)
		}
	}
	if got := backoff(100); got != maxBackoff {
		t.Errorf("backoff(100) = %s, want it capped at %s", got, maxBackoff)
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value  string
		want   time.Duration
		wantOK bool
	}{
		{value: "", wantOK: false},
		{value: "5", want: 5 * time.Second, wantOK: true},
		{value: "0", want: 0, wantOK: true},
		{value: "-1", wantOK: false},
		{value: "soon", wantOK: false},
		{value: "Mon, 02 Jan 2006 15:04:05 GMT", want: 0, wantOK: true}, // a date in the past means now
	}
	for _, tt := range tests {
		got, ok := parseRetryAfter(tt.value)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("parseRetryAfter(%q) = %s, %t, want %s, %t", tt.value, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestMaxWaitFromEnv(t *testing.T) {
	const name = "HTTPRETRY_TEST_MAX_WAIT"
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "", want: DefaultMaxWait},
		{value: "45s", want: 45 * time.Second},
		{value: "0", want: 0},
		{value: "-1m", want: DefaultMaxWait},
		{value: "two minutes", want: DefaultMaxWait},
	}
	for _, tt := range tests {
		t.Setenv(name, tt.value)
		if got := MaxWaitFromEnv(name); got != tt.want {
			t.Errorf("MaxWaitFromEnv() with %q = %s, want %s", tt.value, got, tt.want)
		}
	}
}
