// Copyright 2020 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"time"

	"go.opencensus.io/stats"
	"go.opencensus.io/tag"

	githubstats "github.com/ossf/scorecard/v4/clients/githubrepo/stats"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/log"
)

const (
	// Total wait allowed per request, as a duration (e.g. "2m"). "0" disables waiting.
	maxRateLimitWaitEnv     = "GITHUB_RATE_LIMIT_MAX_WAIT"
	defaultMaxRateLimitWait = 2 * time.Minute
	defaultRetryJitter      = 5 * time.Second
	maxRetryAfterAttempts   = 5
)

var errGitHubRateLimitExceeded = errors.New("github rate limit exceeded")

// MakeRateLimitedTransport returns a RoundTripper which rate limits GitHub requests.
func MakeRateLimitedTransport(innerTransport http.RoundTripper, logger *log.Logger) http.RoundTripper {
	return &rateLimitTransport{
		logger:         logger,
		innerTransport: innerTransport,
		maxWait:        maxRateLimitWaitFromEnv(logger),
		maxJitter:      defaultRetryJitter,
	}
}

func maxRateLimitWaitFromEnv(logger *log.Logger) time.Duration {
	value := os.Getenv(maxRateLimitWaitEnv)
	if value == "" {
		return defaultMaxRateLimitWait
	}
	wait, err := time.ParseDuration(value)
	if err != nil || wait < 0 {
		logger.Info(fmt.Sprintf("invalid %s value %q, using the default of %s",
			maxRateLimitWaitEnv, value, defaultMaxRateLimitWait))
		return defaultMaxRateLimitWait
	}
	return wait
}

// rateLimitTransport is a rate-limit aware http.Transport for GitHub.
type rateLimitTransport struct {
	logger         *log.Logger
	innerTransport http.RoundTripper
	maxWait        time.Duration
	maxJitter      time.Duration
}

// RoundTrip handles caching and rate-limiting of responses from GitHub.
func (gh *rateLimitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return gh.roundTrip(r, 0, 0)
}

func (gh *rateLimitTransport) roundTrip(r *http.Request, waited time.Duration, retries int) (*http.Response, error) {
	// Inner transports add the Authorization header to the request, so each attempt sends a copy.
	resp, err := gh.innerTransport.RoundTrip(r.Clone(r.Context()))
	if err != nil {
		return nil, sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("innerTransport.RoundTrip: %v", err))
	}

	retryValue := resp.Header.Get("Retry-After")
	if retryAfter, err := strconv.Atoi(retryValue); err == nil { // if NO error
		stats.Record(r.Context(), githubstats.RetryAfter.M(int64(retryAfter)))
		duration := time.Duration(retryAfter) * time.Second
		if retries >= maxRetryAfterAttempts || waited+duration > gh.maxWait {
			resp.Body.Close()
			return nil, fmt.Errorf("%w for %s: wait %s to retry",
				errGitHubRateLimitExceeded, resp.Header.Get("X-RateLimit-Resource"), duration)
		}
		gh.logger.Info(fmt.Sprintf("Retry-After header set. Waiting %s to retry...", duration))
		if err := gh.wait(r.Context(), resp, duration); err != nil {
			return nil, err
		}
		gh.logger.Info("Retry-After header set. Retrying...")
		return gh.retry(r, waited+duration, retries+1)
	}

	rateLimit := resp.Header.Get("X-RateLimit-Remaining")
	remaining, err := strconv.Atoi(rateLimit)
	if err != nil {
		//nolint:nilerr // just an error in metadata, response may still be useful?
		return resp, nil
	}
	ctx, err := tag.New(r.Context(), tag.Upsert(githubstats.ResourceType, resp.Header.Get("X-RateLimit-Resource")))
	if err != nil {
		return nil, fmt.Errorf("error updating context: %w", err)
	}
	stats.Record(ctx, githubstats.RemainingTokens.M(int64(remaining)))

	// A 200 that used the last slot is still a success.
	if remaining <= 0 && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
		reset, err := strconv.Atoi(resp.Header.Get("X-RateLimit-Reset"))
		if err != nil {
			//nolint:nilerr // just an error in metadata, response may still be useful?
			return resp, nil
		}

		duration := max(time.Until(time.Unix(int64(reset), 0)), 0)
		if waited+duration > gh.maxWait {
			resp.Body.Close()
			return nil, fmt.Errorf("%w for %s: wait %s to retry",
				errGitHubRateLimitExceeded, resp.Header.Get("X-RateLimit-Resource"), duration)
		}
		if gh.maxJitter > 0 {
			duration += rand.N(gh.maxJitter) //nolint:gosec // spreading retries needs no cryptographic randomness
		}
		gh.logger.Info(fmt.Sprintf("Rate limit exceeded. Waiting %s to retry...", duration))
		if err := gh.wait(r.Context(), resp, duration); err != nil {
			return nil, err
		}
		gh.logger.Info("Rate limit exceeded. Retrying...")
		return gh.retry(r, waited+duration, retries)
	}

	return resp, nil
}

func (gh *rateLimitTransport) wait(ctx context.Context, resp *http.Response, duration time.Duration) error {
	resp.Body.Close()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for GitHub rate limit reset: %w", ctx.Err())
	}
}

// retry sends r again, replaying the body the previous attempt consumed.
func (gh *rateLimitTransport) retry(r *http.Request, waited time.Duration, retries int) (*http.Response, error) {
	if r.GetBody != nil {
		body, err := r.GetBody()
		if err != nil {
			return nil, sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("GetBody: %v", err))
		}
		r = r.Clone(r.Context())
		r.Body = body
	}
	return gh.roundTrip(r, waited, retries)
}
