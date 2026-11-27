// Copyright 2023 OpenSSF Scorecard Authors
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

package ossfuzz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/ossf/scorecard/v4/clients"
)

func TestClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		project    string
		statusFile string
		wantHit    bool
		wantErr    bool
	}{
		{
			name:       "present project",
			project:    "github.com/ossf/scorecard",
			statusFile: "status.json",
			wantHit:    true,
			wantErr:    false,
		},
		{
			name:       "nonexistent project",
			project:    "github.com/not/here",
			statusFile: "status.json",
			wantHit:    false,
			wantErr:    false,
		},
		{
			name:       "nonexistent project which is a substring of a present project",
			project:    "github.com/ossf/score",
			statusFile: "status.json",
			wantHit:    false,
			wantErr:    false,
		},
		{
			name:       "project with main_repo link longer than owner/repo",
			project:    "github.com/google/go-cmp",
			statusFile: "status.json",
			wantHit:    true,
			wantErr:    false,
		},
		{
			name:       "project case-insensitive",
			project:    "github.com/FFTW/fftw3",
			statusFile: "status.json",
			wantHit:    true,
			wantErr:    false,
		},
		{
			name:       "nonexistent status file",
			project:    "github.com/ossf/scorecard",
			statusFile: "not_here.json",
			wantHit:    false,
			wantErr:    true,
		},
		{
			name:       "invalid status file",
			project:    "github.com/ossf/scorecard",
			statusFile: "invalid.json",
			wantHit:    false,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			url := setupServer(t)
			statusURL := fmt.Sprintf("%s/%s", url, tt.statusFile)
			c := CreateOSSFuzzClient(statusURL)
			req := clients.SearchRequest{Query: tt.project}
			resp, err := c.Search(req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("got err %v, wantedErr: %t", err, tt.wantErr)
			}
			if (resp.Hits > 0) != tt.wantHit {
				t.Errorf("wantHit: %t, got %d hits", tt.wantHit, resp.Hits)
			}
		})
	}
}

func TestClientEager(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		project       string
		statusFile    string
		wantHit       bool
		wantSearchErr bool
		wantCreateErr bool
	}{
		{
			name:          "present project",
			project:       "github.com/ossf/scorecard",
			statusFile:    "status.json",
			wantHit:       true,
			wantSearchErr: false,
			wantCreateErr: false,
		},
		{
			name:          "nonexistent project",
			project:       "github.com/not/here",
			statusFile:    "status.json",
			wantHit:       false,
			wantSearchErr: false,
			wantCreateErr: false,
		},
		{
			name:          "nonexistent project which is a substring of a present project",
			project:       "github.com/ossf/score",
			statusFile:    "status.json",
			wantHit:       false,
			wantSearchErr: false,
			wantCreateErr: false,
		},
		{
			name:          "nonexistent status file",
			project:       "github.com/ossf/scorecard",
			statusFile:    "not_here.json",
			wantHit:       false,
			wantSearchErr: false,
			wantCreateErr: true,
		},
		{
			name:          "invalid status file",
			project:       "github.com/ossf/scorecard",
			statusFile:    "invalid.json",
			wantHit:       false,
			wantSearchErr: false,
			wantCreateErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			url := setupServer(t)
			statusURL := fmt.Sprintf("%s/%s", url, tt.statusFile)
			c, err := CreateOSSFuzzClientEager(statusURL)
			if (err != nil) != tt.wantCreateErr {
				t.Fatalf("got err %v, wantCreateErr: %t", err, tt.wantCreateErr)
			}
			if c == nil && tt.wantCreateErr {
				return
			}
			req := clients.SearchRequest{Query: tt.project}
			resp, err := c.Search(req)
			if (err != nil) != tt.wantSearchErr {
				t.Fatalf("got err %v, wantSearchErr: %t", err, tt.wantSearchErr)
			}
			if (resp.Hits > 0) != tt.wantHit {
				t.Errorf("wantHit: %t, got %d hits", tt.wantHit, resp.Hits)
			}
		})
	}
}

func TestClientRetriesServerError(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		b, err := os.ReadFile("./testdata/status.json")
		if err != nil {
			t.Errorf("os.ReadFile: %v", err)
			return
		}
		//nolint:errcheck
		w.Write(b)
	}))
	t.Cleanup(server.Close)

	c := CreateOSSFuzzClient(server.URL + "/status.json")
	resp, err := c.Search(clients.SearchRequest{Query: "github.com/ossf/scorecard"})
	if err != nil {
		t.Fatalf("Search() error = %v, want the server error to be retried", err)
	}
	if resp.Hits != 1 {
		t.Errorf("Search() hits = %d, want 1", resp.Hits)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("server got %d requests, want 2", got)
	}
}

func setupServer(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile("./testdata" + r.URL.Path)
		if err != nil {
			// A missing object is a 404 on Google Cloud Storage, which is not retried.
			t.Logf("os.ReadFile: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		//nolint:errcheck
		w.Write(b)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestAllClientMethods(t *testing.T) {
	t.Parallel()
	c := CreateOSSFuzzClient("testURL")

	// Test InitRepo
	{
		err := c.InitRepo(nil, "", 0)
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("InitRepo: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test IsArchived
	{
		_, err := c.IsArchived()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("IsArchived: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test LocalPath
	{
		_, err := c.LocalPath()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("LocalPath: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListFiles
	{
		_, err := c.ListFiles(nil)
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListFiles: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test GetFileContent
	{
		_, err := c.GetFileContent("")
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("GetFileContent: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test GetBranch
	{
		_, err := c.GetBranch("")
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("GetBranch: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test GetDefaultBranch
	{
		_, err := c.GetDefaultBranch()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("GetDefaultBranch: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test GetOrgRepoClient
	{
		_, err := c.GetOrgRepoClient(context.Background())
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("GetOrgRepoClient: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test GetDefaultBranchName
	{
		_, err := c.GetDefaultBranchName()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("GetDefaultBranchName: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListCommits
	{
		_, err := c.ListCommits()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListCommits: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListIssues
	{
		_, err := c.ListIssues()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListIssues: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListReleases
	{
		_, err := c.ListReleases()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListReleases: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListContributors
	{
		_, err := c.ListContributors()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListContributors: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListSuccessfulWorkflowRuns
	{
		_, err := c.ListSuccessfulWorkflowRuns("")
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListSuccessfulWorkflowRuns: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListCheckRunsForRef
	{
		_, err := c.ListCheckRunsForRef("")
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListCheckRunsForRef: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListStatuses
	{
		_, err := c.ListStatuses("")
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListStatuses: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListWebhooks
	{
		_, err := c.ListWebhooks()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListWebhooks: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test SearchCommits
	{
		_, err := c.SearchCommits(clients.SearchCommitsOptions{})
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("SearchCommits: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test Close
	{
		err := c.Close()
		if err != nil {
			t.Errorf("Close: Expected no error, but got %v", err)
		}
	}

	// Test ListProgrammingLanguages
	{
		_, err := c.ListProgrammingLanguages()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListProgrammingLanguages: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}

	// Test ListLicenses
	{
		_, err := c.ListLicenses()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("ListLicenses: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}
	{
		_, err := c.GetCreatedAt()
		if !errors.Is(err, clients.ErrUnsupportedFeature) {
			t.Errorf("GetCreatedAt: Expected %v, but got %v", clients.ErrUnsupportedFeature, err)
		}
	}
	{
		uri := c.URI()
		if uri != "testURL" {
			t.Errorf("URI: Expected %v, but got %v", "testURL", uri)
		}
	}
}
