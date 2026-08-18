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

package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/log"
	"github.com/ossf/scorecard/v4/options"
	spol "github.com/ossf/scorecard/v4/policy"
	rules "github.com/ossf/scorecard/v4/rule"
)

func sarifMockDocRead() *mockDoc {
	d := map[string]mockCheck{
		"Check-Name": {
			name:        "Check-Name",
			risk:        "High",
			short:       "short description",
			description: "long description\n other line",
			url:         "https://github.com/ossf/scorecard/blob/main/docs/checks.md#check-name",
			tags:        []string{"tag1", "tag2"},
			repos:       []string{"GitHub", "local"},
			remediation: []string{"not-used1", "not-used2"},
		},
		"Check-Name2": {
			name:        "Check-Name2",
			risk:        "Medium",
			short:       "short description 2",
			description: "long description\n other line 2",
			url:         "https://github.com/ossf/scorecard/blob/main/docs/checks.md#check-name2",
			tags:        []string{" tag1 ", " tag2 ", "tag3"},
			repos:       []string{"GitHub", "local"},
			remediation: []string{"not-used1", "not-used2"},
		},
		"Check-Name3": {
			name:        "Check-Name3",
			risk:        "Low",
			short:       "short description 3",
			description: "long description\n other line 3",
			url:         "https://github.com/ossf/scorecard/blob/main/docs/checks.md#check-name3",
			tags:        []string{" tag1", " tag2", "tag3", "tag 4 "},
			repos:       []string{"GitHub", "local"},
			remediation: []string{"not-used1", "not-used2"},
		},
		"Check-Name4": {
			name:        "Check-Name4",
			risk:        "Low",
			short:       "short description 4",
			description: "long description\n other line 4",
			url:         "https://github.com/ossf/scorecard/blob/main/docs/checks.md#check-name4",
			tags:        []string{" tag1", " tag2", "tag3", "tag 4 "},
			repos:       []string{"GitHub"},
			remediation: []string{"not-used1", "not-used2"},
		},
		"Check-Name5": {
			name:        "Check-Name5",
			risk:        "Low",
			short:       "short description 5",
			description: "long description\n other line 5",
			url:         "https://github.com/ossf/scorecard/blob/main/docs/checks.md#check-name5",
			tags:        []string{" tag1", " tag2", "tag3", "tag 4 "},
			repos:       []string{"local"},
			remediation: []string{"not-used1", "not-used2"},
		},
		"Check-Name6": {
			name:        "Check-Name6",
			risk:        "Low",
			short:       "short description 6",
			description: "long description\n other line 6",
			url:         "https://github.com/ossf/scorecard/blob/main/docs/checks.md#check-name6",
			tags:        []string{" tag1", " tag2", "tag3", "tag 4 "},
			repos:       []string{"Git-local"},
			remediation: []string{"not-used1", "not-used2"},
		},
	}

	m := mockDoc{checks: d}
	return &m
}

func TestSARIFOutput(t *testing.T) {
	t.Parallel()

	repoCommit := "68bc59901773ab4c051dfcea0cc4201a1567ab32"
	scorecardCommit := "ccbc59901773ab4c051dfcea0cc4201a1567abdd"
	scorecardVersion := "1.2.3"
	repoName := "repo not used"
	date, e := time.Parse(time.RFC822Z, "17 Aug 21 18:57 +0000")
	if e != nil {
		panic(fmt.Errorf("time.Parse: %w", e))
	}

	checkDocs := sarifMockDocRead()

	//nolint:govet
	tests := []struct {
		name        string
		expected    string
		showDetails bool
		logLevel    log.Level
		result      ScorecardResult
		policy      spol.ScorecardPolicy
	}{
		{
			name:        "check with detail remediation",
			showDetails: true,
			expected:    "./testdata/check-remediation.sarif",
			logLevel:    log.DebugLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name2": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_DISABLED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file1.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad) {BUG();}",
									Remediation: &rules.Remediation{
										Markdown: "this is the custom markdown help",
										Text:     "this is the custom text help",
									},
								},
							},
						},
						Score:  5,
						Reason: "half score reason",
						Name:   "Check-Name",
					},
				},
				Metadata: []string{},
			},
		},
		{
			name:        "check-1",
			showDetails: true,
			expected:    "./testdata/check1.sarif",
			logLevel:    log.DebugLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name2": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_DISABLED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file1.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad) {BUG();}",
								},
							},
						},
						Score:  5,
						Reason: "half score reason",
						Name:   "Check-Name",
					},
				},
				Metadata: []string{},
			},
		},
		{
			name:        "check-2",
			showDetails: true,
			expected:    "./testdata/check2.sarif",
			logLevel:    log.DebugLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name2": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_DISABLED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:   "warn message",
									Path:   "bin/binary.elf",
									Type:   finding.FileTypeBinary,
									Offset: 0,
								},
							},
						},
						Score:  checker.MinResultScore,
						Reason: "min score reason",
						Name:   "Check-Name",
					},
				},
				Metadata: []string{},
			},
		},
		{
			name:        "check-3",
			showDetails: true,
			expected:    "./testdata/check3.sarif",
			logLevel:    log.InfoLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name2": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name3": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:   "warn message",
									Path:   "bin/binary.elf",
									Type:   finding.FileTypeBinary,
									Offset: 0,
								},
							},
						},
						Score:  checker.MinResultScore,
						Reason: "min result reason",
						Name:   "Check-Name",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/doc.txt",
									Type:    finding.FileTypeText,
									Offset:  3,
									Snippet: "some text",
								},
							},
						},
						Score:  checker.MinResultScore,
						Reason: "min result reason",
						Name:   "Check-Name2",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailInfo,
								Msg: checker.LogMessage{
									Text:    "info message",
									Path:    "some/path.js",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG();}",
								},
							},
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "some/path.py",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG2();}",
								},
							},
							{
								Type: checker.DetailDebug,
								Msg: checker.LogMessage{
									Text:    "debug message",
									Path:    "some/path.go",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG5();}",
								},
							},
						},
						Score:  checker.InconclusiveResultScore,
						Reason: "inconclusive reason",
						Name:   "Check-Name3",
					},
				},
				Metadata: []string{},
			},
		},
		{
			name:        "check-4",
			showDetails: true,
			expected:    "./testdata/check4.sarif",
			logLevel:    log.DebugLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name2": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name3": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:   "warn message",
									Path:   "bin/binary.elf",
									Type:   finding.FileTypeBinary,
									Offset: 0,
								},
							},
						},
						Score:  checker.MinResultScore,
						Reason: "min result reason",
						Name:   "Check-Name",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/doc.txt",
									Type:    finding.FileTypeText,
									Offset:  3,
									Snippet: "some text",
								},
							},
						},
						Score:  checker.MinResultScore,
						Reason: "min result reason",
						Name:   "Check-Name2",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailInfo,
								Msg: checker.LogMessage{
									Text:    "info message",
									Path:    "some/path.js",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG();}",
								},
							},
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "some/path.py",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG2();}",
								},
							},
							{
								Type: checker.DetailDebug,
								Msg: checker.LogMessage{
									Text:    "debug message",
									Path:    "some/path.go",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG5();}",
								},
							},
						},
						Score:  checker.InconclusiveResultScore,
						Reason: "inconclusive reason",
						Name:   "Check-Name3",
					},
				},
				Metadata: []string{},
			},
		},
		{
			name:        "check-5",
			showDetails: true,
			expected:    "./testdata/check5.sarif",
			logLevel:    log.WarnLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name": {
						Score: 5,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file1.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad) {BUG();}",
								},
							},
						},
						Score:  6,
						Reason: "six score reason",
						Name:   "Check-Name",
					},
				},
				Metadata: []string{},
			},
		},
		{
			name:        "check-6",
			showDetails: true,
			// https://github.com/github/codeql-action/issues/754
			// Disabled related locations.
			expected: "./testdata/check6.sarif",
			logLevel: log.WarnLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text: "warn message",
									Path: "https://domain.com/something",
									Type: finding.FileTypeURL,
								},
							},
						},
						Score:  6,
						Reason: "six score reason",
						Name:   "Check-Name",
					},
				},
				Metadata: []string{},
			},
		},
		{
			name:        "check-7",
			showDetails: true,
			expected:    "./testdata/check7.sarif",
			logLevel:    log.DebugLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name2": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_DISABLED,
					},
					"Check-Name3": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_DISABLED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:   "warn message",
									Path:   "bin/binary.elf",
									Type:   finding.FileTypeBinary,
									Offset: 0,
								},
							},
						},
						Score:  checker.MinResultScore,
						Reason: "min result reason",
						Name:   "Check-Name",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/doc.txt",
									Type:    finding.FileTypeText,
									Offset:  3,
									Snippet: "some text",
								},
							},
						},
						Score:  checker.MinResultScore,
						Reason: "min result reason",
						Name:   "Check-Name2",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailInfo,
								Msg: checker.LogMessage{
									Text:    "info message",
									Path:    "some/path.js",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG();}",
								},
							},
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "some/path.py",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG2();}",
								},
							},
							{
								Type: checker.DetailDebug,
								Msg: checker.LogMessage{
									Text:    "debug message",
									Path:    "some/path.go",
									Type:    finding.FileTypeSource,
									Offset:  3,
									Snippet: "if (bad) {BUG5();}",
								},
							},
						},
						Score:  checker.InconclusiveResultScore,
						Reason: "inconclusive reason",
						Name:   "Check-Name3",
					},
				},
				Metadata: []string{},
			},
		},
		{
			name:        "check-8",
			showDetails: true,
			expected:    "./testdata/check8.sarif",
			logLevel:    log.DebugLevel,
			policy: spol.ScorecardPolicy{
				Version: 1,
				Policies: map[string]*spol.CheckPolicy{
					"Check-Name4": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name5": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
					"Check-Name6": {
						Score: checker.MaxResultScore,
						Mode:  spol.CheckPolicy_ENFORCED,
					},
				},
			},
			result: ScorecardResult{
				Repo: RepoInfo{
					Name:      repoName,
					CommitSHA: repoCommit,
				},
				Scorecard: ScorecardInfo{
					Version:   scorecardVersion,
					CommitSHA: scorecardCommit,
				},
				Date: date,
				Checks: []checker.CheckResult{
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file1.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad) {BUG();}",
								},
							},
						},
						Score:  5,
						Reason: "half score reason",
						Name:   "Check-Name4",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file1.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad) {BUG();}",
								},
							},
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file2.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad2) {BUG();}",
								},
							},
						},
						Score:  5,
						Reason: "half score reason",
						Name:   "Check-Name",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file1.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad) {BUG();}",
								},
							},
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file2.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad2) {BUG2();}",
								},
							},
						},
						Score:  8,
						Reason: "half score reason",
						Name:   "Check-Name5",
					},
					{
						Details: []checker.CheckDetail{
							{
								Type: checker.DetailWarn,
								Msg: checker.LogMessage{
									Text:    "warn message",
									Path:    "src/file1.cpp",
									Type:    finding.FileTypeSource,
									Offset:  5,
									Snippet: "if (bad) {BUG();}",
								},
							},
						},
						Score:  9,
						Reason: "half score reason",
						Name:   "Check-Name6",
					},
				},
				Metadata: []string{},
			},
		},
	}
	for i := range tests {
		tt := &tests[i] // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var content []byte
			var err error
			content, err = os.ReadFile(tt.expected)
			if err != nil {
				t.Fatalf("%s: cannot read file: %v", tt.name, err)
			}

			var expected bytes.Buffer
			n, err := expected.Write(content)
			if err != nil {
				t.Fatalf("%s: cannot write buffer: %v", tt.name, err)
			}
			if n != len(content) {
				t.Fatalf("%s: write %d bytes but expected %d", tt.name, n, len(content))
			}

			var result bytes.Buffer
			err = tt.result.AsSARIF(tt.showDetails, tt.logLevel, &result,
				checkDocs, &tt.policy, &options.Options{})
			if err != nil {
				t.Fatalf("%s: AsSARIF: %v", tt.name, err)
			}

			r := bytes.Compare(expected.Bytes(), result.Bytes())
			if r != 0 {
				t.Fatalf("%s: invalid result: %d, %s", tt.name, r, cmp.Diff(expected.Bytes(), result.Bytes()))
			}
		})
	}
}

// countingWriter records the number of underlying Write calls it receives.
// bufio.Writer calls the underlying writer only when its buffer is full or Flush is called,
// so a call count > 1 confirms that output was written incrementally.
type countingWriter struct {
	buf   bytes.Buffer
	calls int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.calls++
	return w.buf.Write(p)
}

func TestSARIFStreaming(t *testing.T) {
	t.Parallel()

	// Build a result with enough findings to overflow the default 4096-byte bufio buffer
	// multiple times, verifying that output is written incrementally rather than all at once.
	// Each SARIF result is ~600 bytes; 50 results ≈ 30 KB >> 4096-byte buffer.
	const numDetails = 50
	checkDocs := sarifMockDocRead()
	date, err := time.Parse(time.RFC822Z, "17 Aug 21 18:57 +0000")
	if err != nil {
		t.Fatalf("time.Parse: %v", err)
	}

	details := make([]checker.CheckDetail, numDetails)
	for i := range details {
		details[i] = checker.CheckDetail{
			Type: checker.DetailWarn,
			Msg: checker.LogMessage{
				Text:    fmt.Sprintf("warn message %d", i),
				Path:    fmt.Sprintf("src/file%d.cpp", i),
				Type:    finding.FileTypeSource,
				Offset:  uint(i + 1),
				Snippet: fmt.Sprintf("if (bad%d) {BUG();}", i),
			},
		}
	}

	sc := ScorecardResult{
		Repo:      RepoInfo{Name: "test-repo", CommitSHA: "abc123"},
		Scorecard: ScorecardInfo{Version: "1.0.0", CommitSHA: "def456"},
		Date:      date,
		Checks: []checker.CheckResult{
			{Name: "Check-Name", Score: 5, Reason: "test reason", Details: details},
		},
		Metadata: []string{},
	}
	policy := spol.ScorecardPolicy{
		Version: 1,
		Policies: map[string]*spol.CheckPolicy{
			// Score 10 >= check score 5 → shouldAddLocation returns true for all details.
			"Check-Name": {Score: checker.MaxResultScore, Mode: spol.CheckPolicy_ENFORCED},
		},
	}

	var w countingWriter
	if err := sc.AsSARIF(true, log.DebugLevel, &w, checkDocs, &policy, &options.Options{}); err != nil {
		t.Fatalf("AsSARIF: %v", err)
	}

	// Verify the underlying writer was called more than once, confirming that
	// bufio.Writer flushed incrementally as its buffer filled, not as a single blob.
	if w.calls <= 1 {
		t.Errorf("expected multiple Write calls (got %d); output may not be streamed incrementally", w.calls)
	}

	// Verify the output is valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(w.buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\nfirst 512 bytes:\n%s", err, w.buf.Bytes()[:min(512, w.buf.Len())])
	}

	// Verify top-level SARIF structure.
	if v, _ := parsed["version"].(string); v != "2.1.0" {
		t.Errorf("version = %q, want %q", v, "2.1.0")
	}

	runs, _ := parsed["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1 (Check-Name maps to the local category)", len(runs))
	}

	// Verify that all numDetails results are present in the run.
	localRun, _ := runs[0].(map[string]interface{})
	results, _ := localRun["results"].([]interface{})
	if len(results) != numDetails {
		t.Errorf("len(results) = %d, want %d", len(results), numDetails)
	}
}

func TestSARIFMemoryNotAccumulated(t *testing.T) {
	// Cannot call t.Parallel(): testing.AllocsPerRun panics in parallel tests.

	// Verify that AsSARIF allocations remain bounded even for large result sets.
	// The streaming implementation creates and discards each result struct immediately;
	// it must not accumulate a []result slice proportional to the total finding count.
	//
	// We use testing.AllocsPerRun: the measured alloc count should be proportional
	// to the number of results, not to N^2 or unbounded.
	const numDetails = 200
	checkDocs := sarifMockDocRead()
	date, err := time.Parse(time.RFC822Z, "17 Aug 21 18:57 +0000")
	if err != nil {
		t.Fatalf("time.Parse: %v", err)
	}

	details := make([]checker.CheckDetail, numDetails)
	for i := range details {
		details[i] = checker.CheckDetail{
			Type: checker.DetailWarn,
			Msg: checker.LogMessage{
				Text:   fmt.Sprintf("warn %d", i),
				Path:   fmt.Sprintf("src/file%d.cpp", i),
				Type:   finding.FileTypeSource,
				Offset: uint(i + 1),
			},
		}
	}

	sc := ScorecardResult{
		Repo:      RepoInfo{Name: "test-repo", CommitSHA: "abc123"},
		Scorecard: ScorecardInfo{Version: "1.0.0", CommitSHA: "def456"},
		Date:      date,
		Checks: []checker.CheckResult{
			{Name: "Check-Name", Score: 5, Reason: "test reason", Details: details},
		},
		Metadata: []string{},
	}
	policy := spol.ScorecardPolicy{
		Version: 1,
		Policies: map[string]*spol.CheckPolicy{
			"Check-Name": {Score: checker.MaxResultScore, Mode: spol.CheckPolicy_ENFORCED},
		},
	}

	// Use io.Discard so the output buffer itself does not retain memory.
	allocs := testing.AllocsPerRun(3, func() {
		if err := sc.AsSARIF(true, log.DebugLevel, io.Discard, checkDocs, &policy, &options.Options{}); err != nil {
			t.Errorf("AsSARIF: %v", err)
		}
	})

	// Upper bound: allow up to 50 allocations per result to account for runtime
	// variation (JSON encoding internals, string ops, etc.). This cap is generous
	// enough that it will not produce false failures, yet would catch a regression
	// that materialises an O(N^2) or wildly unbounded allocation pattern.
	const maxAllocsPerResult = 50
	if allocs > float64(numDetails)*maxAllocsPerResult {
		t.Errorf("AllocsPerRun = %.0f, want < %.0f (%d results × %d allocs/result limit)",
			allocs, float64(numDetails)*maxAllocsPerResult, numDetails, maxAllocsPerResult)
	}
}
