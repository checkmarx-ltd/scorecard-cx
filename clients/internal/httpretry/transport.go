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

// Package httpretry retries requests to third-party services that fail for a short time,
// such as a rate limit, a server error or a maintenance page. It follows the GitHub
// rate-limit transport (clients/githubrepo/roundtripper/rate_limit.go): a total time budget
// read from the environment, random jitter, a cap on Retry-After attempts, waits that stop
// on cancellation, and a fresh copy of the request, with its body replayed, on every retry.
package httpretry

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"time"

	sce "github.com/ossf/scorecard/v4/errors"
)

const (
	// DefaultMaxWait is the time a request may spend on retries, waits and attempts together.
	DefaultMaxWait = 2 * time.Minute

	retryJitter           = 5 * time.Second
	maxRetryAfterAttempts = 5
	defaultAttemptTimeout = 30 * time.Second
	initialBackoff        = time.Second
	maxBackoff            = 30 * time.Second
	// maxDrainBytes caps how much of a discarded body is read so the connection can be reused.
	maxDrainBytes = 64 * 1024
)

// Transport retries a request while its outcome is retryable and the time spent on it, waits
// and attempts together, stays within maxWait. A network error, HTTP 429 and HTTP 5xx are
// retryable by default. The wait follows Retry-After when the reply has one (at most
// maxRetryAfterAttempts times), otherwise an exponential backoff, plus random jitter. When it
// stops retrying, Transport returns the last reply so the caller can report what it got.
type Transport struct {
	innerTransport http.RoundTripper
	retryable      func(*http.Response) bool
	wait           func(context.Context, time.Duration) error
	maxWait        time.Duration
	maxJitter      time.Duration
	attemptTimeout time.Duration
}

// New returns a Transport that sends attempts through innerTransport (http.DefaultTransport
// when nil). retryable decides which replies are retried (RetryableStatus when nil). A maxWait
// of 0 disables retries.
func New(innerTransport http.RoundTripper, maxWait time.Duration, retryable func(*http.Response) bool) *Transport {
	if innerTransport == nil {
		innerTransport = http.DefaultTransport
	}
	if retryable == nil {
		retryable = RetryableStatus
	}
	return &Transport{
		innerTransport: innerTransport,
		retryable:      retryable,
		wait:           wait,
		maxWait:        maxWait,
		maxJitter:      retryJitter,
		attemptTimeout: defaultAttemptTimeout,
	}
}

// RetryableStatus reports whether a reply is a rate limit or a server error.
func RetryableStatus(resp *http.Response) bool {
	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError
}

// MaxWaitFromEnv reads a Go duration such as "2m" from the environment variable name.
// An unset, invalid or negative value gives DefaultMaxWait.
func MaxWaitFromEnv(name string) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return DefaultMaxWait
	}
	maxWait, err := time.ParseDuration(value)
	if err != nil || maxWait < 0 {
		return DefaultMaxWait
	}
	return maxWait
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()
	// spent counts the waits and the time taken by attempts, so slow failing attempts cannot
	// stretch a request far beyond maxWait.
	var spent time.Duration
	retryAfterAttempts := 0
	for attempt := 0; ; attempt++ {
		attemptStart := time.Now()
		resp, err := t.attempt(r)
		spent += time.Since(attemptStart)
		if ctxErr := ctx.Err(); ctxErr != nil {
			closeBody(resp)
			return nil, fmt.Errorf("request ended: %w", ctxErr)
		}
		if err == nil && !t.retryable(resp) {
			return resp, nil
		}

		duration := backoff(attempt)
		if resp != nil {
			if retryAfter, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
				if retryAfterAttempts >= maxRetryAfterAttempts {
					return resp, nil
				}
				retryAfterAttempts++
				duration = retryAfter
			}
		}
		if t.maxJitter > 0 {
			duration += rand.N(t.maxJitter) //nolint:gosec // spreading retries needs no cryptographic randomness
		}
		if spent+duration > t.maxWait {
			return resp, err
		}

		closeBody(resp)
		if err := t.wait(ctx, duration); err != nil {
			return nil, err
		}
		spent += duration

		if r, err = replayBody(r); err != nil {
			return nil, err
		}
	}
}

// attempt sends a copy of r, bounded by the attempt timeout. The timeout keeps running until
// the reply's body is closed, so it also bounds reading the body.
func (t *Transport) attempt(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(r.Context(), t.attemptTimeout)
	resp, err := t.innerTransport.RoundTrip(r.Clone(ctx))
	if err != nil {
		cancel()
		return nil, err //nolint:wrapcheck // the caller wraps transport errors
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// replayBody returns r with a fresh body when the previous attempt consumed it.
func replayBody(r *http.Request) (*http.Request, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return r, nil
	}
	if r.GetBody == nil {
		return nil, sce.WithMessage(sce.ErrScorecardInternal, "cannot retry a request whose body cannot be replayed")
	}
	body, err := r.GetBody()
	if err != nil {
		return nil, sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("GetBody: %v", err))
	}
	r = r.Clone(r.Context())
	r.Body = body
	return r, nil
}

// backoff doubles from initialBackoff up to maxBackoff.
func backoff(attempt int) time.Duration {
	if attempt >= 5 { // initialBackoff<<5 is already past maxBackoff
		return maxBackoff
	}
	return min(initialBackoff<<attempt, maxBackoff)
}

// parseRetryAfter reads a Retry-After value given in seconds or as an HTTP date.
func parseRetryAfter(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second, true
	}
	if date, err := http.ParseTime(value); err == nil {
		return max(time.Until(date), 0), true
	}
	return 0, false
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting to retry: %w", ctx.Err())
	}
}

// closeBody discards a reply that will not be returned.
func closeBody(resp *http.Response) {
	if resp == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
	_ = resp.Body.Close()
}

// cancelOnClose releases the attempt's timeout once the body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close() //nolint:wrapcheck // passes the body's own error through
}
