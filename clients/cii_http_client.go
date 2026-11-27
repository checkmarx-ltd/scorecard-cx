// Copyright 2021 OpenSSF Scorecard Authors
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

package clients

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ossf/scorecard/v4/clients/internal/httpretry"
)

const (
	// ciiMaxWaitEnv caps the total wait between retries of one badge request, as a Go
	// duration (e.g. "2m"). "0" disables retries.
	ciiMaxWaitEnv = "CII_BEST_PRACTICES_MAX_WAIT"
	// maxResponseBodyShown caps how much of an unexpected reply's body goes into an error.
	maxResponseBodyShown = 256
)

var errUnexpectedStatus = errors.New("unexpected status from the OpenSSF Best Practices API")

// httpClientCIIBestPractices implements the CIIBestPracticesClient interface.
// Rate limits, server errors and HTML pages are retried within maxWait.
type httpClientCIIBestPractices struct {
	transport http.RoundTripper
	maxWait   time.Duration
}

// newHTTPClientCIIBestPractices returns a client whose retry budget comes from ciiMaxWaitEnv.
func newHTTPClientCIIBestPractices() *httpClientCIIBestPractices {
	return &httpClientCIIBestPractices{maxWait: httpretry.MaxWaitFromEnv(ciiMaxWaitEnv)}
}

// retryableBadgeReply reports whether a reply is worth retrying. The API only answers with
// JSON, so an HTML page is an error or maintenance page served in front of it.
func retryableBadgeReply(resp *http.Response) bool {
	return httpretry.RetryableStatus(resp) ||
		strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

// GetBadgeLevel implements CIIBestPracticesClient.GetBadgeLevel.
func (client *httpClientCIIBestPractices) GetBadgeLevel(ctx context.Context, uri string) (BadgeLevel, error) {
	// The escaped form is what the API redirects an unescaped query to, so it saves a request.
	badgeURL := "https://www.bestpractices.dev/projects.json?url=" + url.QueryEscape("https://"+uri)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, badgeURL, nil)
	if err != nil {
		return Unknown, fmt.Errorf("error during http.NewRequestWithContext: %w", err)
	}

	httpClient := http.Client{
		Transport: httpretry.New(client.transport, client.maxWait, retryableBadgeReply),
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Unknown, fmt.Errorf("error during http.Do: %w", err)
	}
	defer resp.Body.Close()

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return Unknown, fmt.Errorf("error during io.ReadAll: %w", err)
	}

	// The status and the start of the body are kept in the error so an unexpected reply,
	// such as an HTML error page, can be identified from the logs.
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Unknown, fmt.Errorf("%w: %s", errUnexpectedStatus, describeResponse(resp, jsonData))
	}

	parsedResponse, err := ParseBadgeResponseFromJSON(jsonData)
	if err != nil {
		return Unknown, fmt.Errorf("error during json parsing: %w (%s)", err, describeResponse(resp, jsonData))
	}
	if len(parsedResponse) < 1 {
		return NotFound, nil
	}
	return parsedResponse[0].getBadgeLevel()
}

// describeResponse summarizes a reply as its status, content type and the start of its body.
func describeResponse(resp *http.Response, body []byte) string {
	shown := string(body)
	if len(body) > maxResponseBodyShown {
		shown = string(body[:maxResponseBodyShown]) + "..."
	}
	return fmt.Sprintf("HTTP %d, Content-Type %q, body %q", resp.StatusCode, resp.Header.Get("Content-Type"), shown)
}
