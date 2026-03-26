package triage

import (
	"strings"
	"testing"
)

func TestNormalizeOutputFormat(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: "markdown"},
		{input: "markdown", want: "markdown"},
		{input: "md", want: "markdown"},
		{input: "text", want: "text"},
		{input: "txt", want: "text"},
	}

	for _, tt := range tests {
		got, err := NormalizeOutputFormat(tt.input)
		if err != nil {
			t.Fatalf("NormalizeOutputFormat(%q) returned error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeOutputFormat(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}

	if _, err := NormalizeOutputFormat("html"); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestNormalizeExtraRootMode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: "external"},
		{input: "external", want: "external"},
		{input: "evidence", want: "external"},
		{input: "local", want: "local"},
		{input: "host", want: "local"},
	}

	for _, tt := range tests {
		got, err := NormalizeExtraRootMode(tt.input)
		if err != nil {
			t.Fatalf("NormalizeExtraRootMode(%q) returned error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeExtraRootMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}

	if _, err := NormalizeExtraRootMode("mounted"); err == nil {
		t.Fatal("expected error for unsupported extra-root mode")
	}
}

func TestRenderMarkdownSummary(t *testing.T) {
	report := &Report{
		Host: HostInfo{
			Hostname: "host-a",
			OS:       "windows",
			Arch:     "amd64",
		},
		Assessment: buildAssessment("high", "host-ioc-found", []string{"在 Apifox 目录中发现 IOC"}),
		ThreatIntel: ThreatIntel{
			ConfirmedBehaviors: []string{"样本会窃取凭证"},
			CapabilityNotes:    []string{"样本可远程拉取后续脚本"},
		},
		Profiles: []ProfileReport{
			{
				Username:   "alice",
				Home:       `C:\Users\alice`,
				Assessment: buildAssessment("high", "host-ioc-found", []string{"发现 IOC 文件"}),
				ApifoxHits: []FileHit{
					{
						Path:          `C:\Users\alice\AppData\Roaming\Apifox\log.txt`,
						MatchedTokens: []string{"apifox.it.com"},
						Review: ReviewGuidance{
							Standard:   "direct_ioc",
							Confidence: "高",
						},
					},
				},
				SensitiveArtifacts: []SensitiveArtifact{
					{Name: ".ssh", Exists: true},
				},
			},
		},
		Recommendations: []string{"立即隔离主机"},
	}

	got := RenderMarkdownSummary(report)
	requiredFragments := []string{
		"# Apifox 供应链事件分诊报告",
		"## 主机结论",
		"- 中招判断：`已发现中招迹象`",
		"## 用户 `alice`",
		"- IOC 命中：`C:\\Users\\alice\\AppData\\Roaming\\Apifox\\log.txt` [apifox.it.com] 复审=`直接 IOC/高`",
		"## 建议的下一步",
	}

	for _, fragment := range requiredFragments {
		if !strings.Contains(got, fragment) {
			t.Fatalf("markdown summary missing fragment %q\n%s", fragment, got)
		}
	}
}
