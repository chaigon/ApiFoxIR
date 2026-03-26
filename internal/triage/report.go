package triage

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type Config struct {
	OutputDir          string
	MaxFileSize        int64
	CopyApifoxEvidence bool
	IncidentStart      time.Time
	IncidentEnd        time.Time
	ExtraRoots         []string
	ExtraRootMode      string
}

type Report struct {
	GeneratedAt                time.Time             `json:"generated_at"`
	IncidentName               string                `json:"incident_name"`
	IncidentStart              time.Time             `json:"incident_start"`
	IncidentEnd                time.Time             `json:"incident_end"`
	Host                       HostInfo              `json:"host"`
	ThreatIntel                ThreatIntel           `json:"threat_intel"`
	ReviewStandards            []ReviewStandard      `json:"review_standards"`
	Profiles                   []ProfileReport       `json:"profiles"`
	SystemPersistenceLocations []PersistenceLocation `json:"system_persistence_locations,omitempty"`
	SystemPersistenceFindings  []PersistenceFinding  `json:"system_persistence_findings,omitempty"`
	WindowsArtifacts           WindowsArtifacts      `json:"windows_artifacts,omitempty"`
	ExtraRootFindings          []ExtraRootFinding    `json:"extra_root_findings,omitempty"`
	ExtraRootMode              string                `json:"extra_root_mode,omitempty"`
	Processes                  []ProcessInfo         `json:"processes,omitempty"`
	C2ContactEvidence          C2ContactEvidence     `json:"c2_contact_evidence"`
	LeakageAnalysis            LeakageAnalysis       `json:"leakage_analysis"`
	Assessment                 Assessment            `json:"assessment"`
	Recommendations            []string              `json:"recommendations"`
	EvidenceDir                string                `json:"evidence_dir,omitempty"`
	Errors                     []string              `json:"errors,omitempty"`
}

type HostInfo struct {
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	CurrentUser string `json:"current_user"`
}

type ProfileReport struct {
	Username               string                `json:"username"`
	Home                   string                `json:"home"`
	ApifoxDirs             []DirectoryStatus     `json:"apifox_dirs"`
	ApifoxHits             []FileHit             `json:"apifox_hits,omitempty"`
	SensitiveArtifacts     []SensitiveArtifact   `json:"sensitive_artifacts"`
	CommandHistoryHits     []CommandHistoryHit   `json:"command_history_hits,omitempty"`
	PersistenceLocations   []PersistenceLocation `json:"persistence_locations,omitempty"`
	PersistenceFindings    []PersistenceFinding  `json:"persistence_findings,omitempty"`
	ActivityDuringIncident bool                  `json:"activity_during_incident"`
	Assessment             Assessment            `json:"assessment"`
	Notes                  []string              `json:"notes,omitempty"`
}

type DirectoryStatus struct {
	Path        string    `json:"path"`
	Source      string    `json:"source"`
	Exists      bool      `json:"exists"`
	LatestMTime time.Time `json:"latest_mtime,omitempty"`
}

type FileHit struct {
	Path           string         `json:"path"`
	MatchedTokens  []string       `json:"matched_tokens"`
	Categories     []string       `json:"categories"`
	Size           int64          `json:"size"`
	SHA256         string         `json:"sha256"`
	ModifiedAt     time.Time      `json:"modified_at"`
	CopiedEvidence string         `json:"copied_evidence,omitempty"`
	Review         ReviewGuidance `json:"review"`
}

type SensitiveArtifact struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Path       string    `json:"path"`
	Exists     bool      `json:"exists"`
	FileCount  int       `json:"file_count,omitempty"`
	TotalSize  int64     `json:"total_size,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
	Truncated  bool      `json:"truncated,omitempty"`
	// CredentialFindings 内容敏感性分析结果，仅文件类型填充
	CredentialFindings []string `json:"credential_findings,omitempty"`
	// LevelDBHits LevelDB 专项扫描命中（仅 Apifox 数据目录有效）
	LevelDBHits []FileHit `json:"leveldb_hits,omitempty"`
}

type ExtraRootFinding struct {
	Root string    `json:"root"`
	Hits []FileHit `json:"hits,omitempty"`
}

type ProcessInfo struct {
	PID  string `json:"pid"`
	Name string `json:"name"`
}

type ThreatIntel struct {
	ConfirmedBehaviors []string          `json:"confirmed_behaviors"`
	CapabilityNotes    []string          `json:"capability_notes"`
	Inferences         []string          `json:"inferences"`
	Sources            []SourceReference `json:"sources"`
}

type SourceReference struct {
	Title         string `json:"title"`
	URL           string `json:"url"`
	PublishedDate string `json:"published_date,omitempty"`
	Notes         string `json:"notes,omitempty"`
}

type PersistenceLocation struct {
	Path        string    `json:"path"`
	Kind        string    `json:"kind"`
	Scope       string    `json:"scope"`
	Exists      bool      `json:"exists"`
	LatestMTime time.Time `json:"latest_mtime,omitempty"`
}

type PersistenceFinding struct {
	Path          string         `json:"path"`
	Kind          string         `json:"kind"`
	Scope         string         `json:"scope"`
	Size          int64          `json:"size"`
	SHA256        string         `json:"sha256,omitempty"`
	ModifiedAt    time.Time      `json:"modified_at"`
	MatchedTokens []string       `json:"matched_tokens,omitempty"`
	Markers       []string       `json:"markers,omitempty"`
	Reasons       []string       `json:"reasons"`
	Review        ReviewGuidance `json:"review"`
}

type WindowsArtifacts struct {
	RegistryAutoruns []RegistryAutorun `json:"registry_autoruns,omitempty"`
	PrefetchHits     []PrefetchHit     `json:"prefetch_hits,omitempty"`
}

type CommandHistoryHit struct {
	Path          string         `json:"path"`
	Shell         string         `json:"shell"`
	LineNumber    int            `json:"line_number"`
	MatchedTokens []string       `json:"matched_tokens,omitempty"`
	Markers       []string       `json:"markers,omitempty"`
	Reasons       []string       `json:"reasons"`
	Review        ReviewGuidance `json:"review"`
}

type RegistryAutorun struct {
	Key           string         `json:"key"`
	Scope         string         `json:"scope"`
	ValueName     string         `json:"value_name"`
	ValueType     string         `json:"value_type"`
	Command       string         `json:"command"`
	MatchedTokens []string       `json:"matched_tokens,omitempty"`
	Markers       []string       `json:"markers,omitempty"`
	PathMarkers   []string       `json:"path_markers,omitempty"`
	Reasons       []string       `json:"reasons"`
	Review        ReviewGuidance `json:"review"`
}

type PrefetchHit struct {
	Path       string         `json:"path"`
	Name       string         `json:"name"`
	ModifiedAt time.Time      `json:"modified_at"`
	Reasons    []string       `json:"reasons"`
	Review     ReviewGuidance `json:"review"`
}

type ReviewStandard struct {
	Name        string   `json:"name"`
	Confidence  string   `json:"confidence"`
	Description string   `json:"description"`
	ReviewSteps []string `json:"review_steps"`
}

type ReviewGuidance struct {
	Required     bool     `json:"required"`
	Standard     string   `json:"standard"`
	StandardText string   `json:"standard_text"`
	Confidence   string   `json:"confidence"`
	Why          string   `json:"why"`
	Steps        []string `json:"steps"`
}

type Assessment struct {
	Severity             string   `json:"severity"`
	SeverityText         string   `json:"severity_text"`
	Label                string   `json:"label"`
	LabelText            string   `json:"label_text"`
	CompromiseStatus     string   `json:"compromise_status"`
	CompromiseStatusText string   `json:"compromise_status_text"`
	Reasons              []string `json:"reasons"`
}

func WriteJSON(report *Report, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func NormalizeOutputFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "md", "markdown":
		return "markdown", nil
	case "txt", "text":
		return "text", nil
	default:
		return "", fmt.Errorf("不支持的输出格式 %q，可选 markdown、text", format)
	}
}

func NormalizeExtraRootMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "external", "evidence":
		return "external", nil
	case "local", "host":
		return "local", nil
	default:
		return "", fmt.Errorf("不支持的 extra-root 模式 %q，可选 external、local", mode)
	}
}

func SummaryFileName(format string) string {
	switch format {
	case "markdown":
		return "report.md"
	default:
		return "report.txt"
	}
}

func RenderSummary(report *Report, format string) (string, error) {
	normalized, err := NormalizeOutputFormat(format)
	if err != nil {
		return "", err
	}
	switch normalized {
	case "markdown":
		return RenderMarkdownSummary(report), nil
	default:
		return RenderTextSummary(report), nil
	}
}

func RenderTextSummary(report *Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "主机：%s (%s/%s)\n", report.Host.Hostname, report.Host.OS, report.Host.Arch)
	compromiseStatusText := report.Assessment.CompromiseStatusText
	if compromiseStatusText == "" {
		compromiseStatusText = compromiseStatusCN(report.Assessment.CompromiseStatus)
	}
	labelText := report.Assessment.LabelText
	if labelText == "" {
		labelText = assessmentLabelCN(report.Assessment.Label)
	}
	severityText := report.Assessment.SeverityText
	if severityText == "" {
		severityText = severityCN(report.Assessment.Severity)
	}
	fmt.Fprintf(&b, "中招判断：%s\n", compromiseStatusText)
	fmt.Fprintf(&b, "技术结论：%s [%s]\n", labelText, severityText)
	if len(report.Assessment.Reasons) > 0 {
		for _, reason := range report.Assessment.Reasons {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
	}

	totalHits := 0
	totalProfilesWithApifox := 0
	totalUserPersistenceFindings := 0
	totalHistoryHits := 0
	for _, profile := range report.Profiles {
		if hasExistingApifoxDir(profile.ApifoxDirs) {
			totalProfilesWithApifox++
		}
		totalHits += len(profile.ApifoxHits)
		totalUserPersistenceFindings += len(profile.PersistenceFindings)
		totalHistoryHits += len(profile.CommandHistoryHits)
	}

	if len(report.ThreatIntel.ConfirmedBehaviors) > 0 || len(report.ThreatIntel.CapabilityNotes) > 0 {
		fmt.Fprintf(&b, "\n威胁画像：\n")
		if len(report.ThreatIntel.ConfirmedBehaviors) > 0 {
			fmt.Fprintf(&b, "- 已确认：%s\n", report.ThreatIntel.ConfirmedBehaviors[0])
		}
		if len(report.ThreatIntel.CapabilityNotes) > 0 {
			fmt.Fprintf(&b, "- 能力说明：%s\n", report.ThreatIntel.CapabilityNotes[0])
		}
	}

	fmt.Fprintf(&b, "\n已扫描用户：%d\n", len(report.Profiles))
	fmt.Fprintf(&b, "发现 Apifox 痕迹的用户：%d\n", totalProfilesWithApifox)
	fmt.Fprintf(&b, "Apifox IOC 文件命中：%d\n", totalHits)
	fmt.Fprintf(&b, "需复审的命令历史命中：%d\n", totalHistoryHits)
	fmt.Fprintf(&b, "用户级持久化命中：%d\n", totalUserPersistenceFindings)
	fmt.Fprintf(&b, "系统级持久化命中：%d\n", len(report.SystemPersistenceFindings))
	fmt.Fprintf(&b, "Windows 注册表启动项命中：%d\n", len(report.WindowsArtifacts.RegistryAutoruns))
	fmt.Fprintf(&b, "Windows Prefetch 命中：%d\n", len(report.WindowsArtifacts.PrefetchHits))
	fmt.Fprintf(&b, "人工复审项总数：%d\n", countManualReviewItems(report))
	fmt.Fprintf(&b, "当前运行中的 Apifox 进程：%d\n", len(report.Processes))

	sort.Slice(report.Profiles, func(i, j int) bool {
		return report.Profiles[i].Username < report.Profiles[j].Username
	})

	for _, profile := range report.Profiles {
		profileCompromiseText := profile.Assessment.CompromiseStatusText
		if profileCompromiseText == "" {
			profileCompromiseText = compromiseStatusCN(profile.Assessment.CompromiseStatus)
		}
		profileLabelText := profile.Assessment.LabelText
		if profileLabelText == "" {
			profileLabelText = assessmentLabelCN(profile.Assessment.Label)
		}
		fmt.Fprintf(&b, "\n[%s] %s\n", profile.Username, profileCompromiseText)
		fmt.Fprintf(&b, "技术结论：%s\n", profileLabelText)
		if profile.Home != "" {
			fmt.Fprintf(&b, "主目录：%s\n", profile.Home)
		}
		if len(profile.Assessment.Reasons) > 0 {
			for _, reason := range profile.Assessment.Reasons {
				fmt.Fprintf(&b, "- %s\n", reason)
			}
		}
		if len(profile.ApifoxHits) > 0 {
			fmt.Fprintf(&b, "主要 IOC 命中：\n")
			limit := min(len(profile.ApifoxHits), 5)
			for i := 0; i < limit; i++ {
				hit := profile.ApifoxHits[i]
				fmt.Fprintf(&b, "- %s [%s] 复审=%s/%s\n", hit.Path, strings.Join(hit.MatchedTokens, ", "), reviewStandardCN(hit.Review.Standard), hit.Review.Confidence)
			}
		}
		if len(profile.CommandHistoryHits) > 0 {
			fmt.Fprintf(&b, "命令历史命中：\n")
			limit := min(len(profile.CommandHistoryHits), 3)
			for i := 0; i < limit; i++ {
				hit := profile.CommandHistoryHits[i]
				summary := strings.Join(hit.Reasons, "; ")
				if len(hit.MatchedTokens) > 0 {
					summary = strings.Join(hit.MatchedTokens, ", ")
				}
				fmt.Fprintf(&b, "- %s:%d [%s] 复审=%s/%s\n", hit.Path, hit.LineNumber, summary, reviewStandardCN(hit.Review.Standard), hit.Review.Confidence)
			}
		}
		if len(profile.PersistenceFindings) > 0 {
			fmt.Fprintf(&b, "持久化命中：\n")
			limit := min(len(profile.PersistenceFindings), 3)
			for i := 0; i < limit; i++ {
				finding := profile.PersistenceFindings[i]
				markerSummary := strings.Join(finding.Reasons, "; ")
				if len(finding.MatchedTokens) > 0 {
					markerSummary = strings.Join(finding.MatchedTokens, ", ")
				}
				fmt.Fprintf(&b, "- %s [%s] 复审=%s/%s\n", finding.Path, markerSummary, reviewStandardCN(finding.Review.Standard), finding.Review.Confidence)
			}
		}
		exposedCount := 0
		for _, artifact := range profile.SensitiveArtifacts {
			if artifact.Exists {
				exposedCount++
			}
		}
		fmt.Fprintf(&b, "存在的敏感路径：%d/%d\n", exposedCount, len(profile.SensitiveArtifacts))
	}

	if len(report.SystemPersistenceFindings) > 0 {
		fmt.Fprintf(&b, "\n系统级持久化命中：\n")
		limit := min(len(report.SystemPersistenceFindings), 3)
		for i := 0; i < limit; i++ {
			finding := report.SystemPersistenceFindings[i]
			markerSummary := strings.Join(finding.Reasons, "; ")
			if len(finding.MatchedTokens) > 0 {
				markerSummary = strings.Join(finding.MatchedTokens, ", ")
			}
			fmt.Fprintf(&b, "- %s [%s] 复审=%s/%s\n", finding.Path, markerSummary, reviewStandardCN(finding.Review.Standard), finding.Review.Confidence)
		}
	}

	if len(report.WindowsArtifacts.RegistryAutoruns) > 0 {
		fmt.Fprintf(&b, "\nWindows 注册表启动项：\n")
		limit := min(len(report.WindowsArtifacts.RegistryAutoruns), 3)
		for i := 0; i < limit; i++ {
			entry := report.WindowsArtifacts.RegistryAutoruns[i]
			summary := strings.Join(entry.Reasons, "; ")
			if len(entry.MatchedTokens) > 0 {
				summary = strings.Join(entry.MatchedTokens, ", ")
			}
			fmt.Fprintf(&b, "- %s\\%s [%s] 复审=%s/%s\n", entry.Key, entry.ValueName, summary, reviewStandardCN(entry.Review.Standard), entry.Review.Confidence)
		}
	}

	if len(report.WindowsArtifacts.PrefetchHits) > 0 {
		fmt.Fprintf(&b, "\nWindows Prefetch 命中：\n")
		limit := min(len(report.WindowsArtifacts.PrefetchHits), 3)
		for i := 0; i < limit; i++ {
			hit := report.WindowsArtifacts.PrefetchHits[i]
			fmt.Fprintf(&b, "- %s [%s] 复审=%s/%s\n", hit.Path, strings.Join(hit.Reasons, "; "), reviewStandardCN(hit.Review.Standard), hit.Review.Confidence)
		}
	}

	if len(report.ExtraRootFindings) > 0 {
		fmt.Fprintf(&b, "\n额外扫描目录：\n")
		if extraRootMode(report.ExtraRootMode) == "external" {
			fmt.Fprintf(&b, "- 这些目录按外部证据处理：命中不会并入当前主机的中招结论或本机凭证泄露推断。\n")
		}
		for _, finding := range report.ExtraRootFindings {
			fmt.Fprintf(&b, "- %s：%d 个命中\n", finding.Root, len(finding.Hits))
		}
	}

	if report.C2ContactEvidence.ContactConfirmed || len(report.C2ContactEvidence.DNSCacheHits) > 0 ||
		len(report.C2ContactEvidence.ActiveConnections) > 0 || len(report.C2ContactEvidence.ElectronNetworkHits) > 0 {
		fmt.Fprintf(&b, "\nC2 通信证据（是否被远程控制）：\n")
		if report.C2ContactEvidence.ContactNote != "" {
			fmt.Fprintf(&b, "  概述：%s\n", report.C2ContactEvidence.ContactNote)
		}
		if len(report.C2ContactEvidence.DNSCacheHits) > 0 {
			fmt.Fprintf(&b, "  DNS 缓存命中（确认曾解析 C2 域名）：\n")
			for _, h := range report.C2ContactEvidence.DNSCacheHits {
				fmt.Fprintf(&b, "  - %s\n", h)
			}
		}
		if len(report.C2ContactEvidence.ActiveConnections) > 0 {
			fmt.Fprintf(&b, "  [!] 当前活跃 C2 连接（进程仍在通信）：\n")
			for _, c := range report.C2ContactEvidence.ActiveConnections {
				fmt.Fprintf(&b, "  - %s\n", c)
			}
		}
		if len(report.C2ContactEvidence.ElectronNetworkHits) > 0 {
			fmt.Fprintf(&b, "  Electron Network 缓存命中（历史请求残留）：\n")
			for _, h := range report.C2ContactEvidence.ElectronNetworkHits {
				fmt.Fprintf(&b, "  - %s [%s]\n", h.Path, strings.Join(h.MatchedTokens, ", "))
			}
		}
	}

	if len(report.LeakageAnalysis.ExposedTypes) > 0 || report.LeakageAnalysis.RiskSummary != "" {
		fmt.Fprintf(&b, "\n泄露内容推断：\n")
		if report.LeakageAnalysis.RiskSummary != "" {
			fmt.Fprintf(&b, "  概述：%s\n", report.LeakageAnalysis.RiskSummary)
		}
		if report.LeakageAnalysis.PostExploitationRisk {
			fmt.Fprintf(&b, "  [!] 二阶段风险：%s\n", report.LeakageAnalysis.PostExploitationNote)
		}
		for _, ct := range report.LeakageAnalysis.ExposedTypes {
			fmt.Fprintf(&b, "- [%s] %s（风险：%s）\n", ct.Kind, ct.Label, riskLevelCN(ct.RiskLevel))
			fmt.Fprintf(&b, "  证据：%s\n", ct.Evidence)
			fmt.Fprintf(&b, "  处置：%s\n", ct.ActionRequired)
		}
	}

	if len(report.Recommendations) > 0 {
		fmt.Fprintf(&b, "\n建议的下一步：\n")
		for _, step := range report.Recommendations {
			fmt.Fprintf(&b, "- %s\n", step)
		}
	}

	if len(report.Errors) > 0 {
		fmt.Fprintf(&b, "\n警告：\n")
		for _, msg := range report.Errors {
			fmt.Fprintf(&b, "- %s\n", msg)
		}
	}

	return strings.TrimSpace(b.String())
}

func RenderMarkdownSummary(report *Report) string {
	var b strings.Builder

	compromiseStatusText := report.Assessment.CompromiseStatusText
	if compromiseStatusText == "" {
		compromiseStatusText = compromiseStatusCN(report.Assessment.CompromiseStatus)
	}
	labelText := report.Assessment.LabelText
	if labelText == "" {
		labelText = assessmentLabelCN(report.Assessment.Label)
	}
	severityText := report.Assessment.SeverityText
	if severityText == "" {
		severityText = severityCN(report.Assessment.Severity)
	}

	totalHits := 0
	totalProfilesWithApifox := 0
	totalUserPersistenceFindings := 0
	totalHistoryHits := 0
	for _, profile := range report.Profiles {
		if hasExistingApifoxDir(profile.ApifoxDirs) {
			totalProfilesWithApifox++
		}
		totalHits += len(profile.ApifoxHits)
		totalUserPersistenceFindings += len(profile.PersistenceFindings)
		totalHistoryHits += len(profile.CommandHistoryHits)
	}

	fmt.Fprintf(&b, "# Apifox 供应链事件分诊报告\n\n")
	fmt.Fprintf(&b, "## 主机结论\n\n")
	fmt.Fprintf(&b, "- 主机：`%s` (`%s/%s`)\n", report.Host.Hostname, report.Host.OS, report.Host.Arch)
	fmt.Fprintf(&b, "- 中招判断：`%s`\n", compromiseStatusText)
	fmt.Fprintf(&b, "- 技术结论：`%s [%s]`\n", labelText, severityText)
	if len(report.Assessment.Reasons) > 0 {
		for _, reason := range report.Assessment.Reasons {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
	}

	if len(report.ThreatIntel.ConfirmedBehaviors) > 0 || len(report.ThreatIntel.CapabilityNotes) > 0 {
		fmt.Fprintf(&b, "\n## 威胁画像\n\n")
		if len(report.ThreatIntel.ConfirmedBehaviors) > 0 {
			fmt.Fprintf(&b, "- 已确认：%s\n", report.ThreatIntel.ConfirmedBehaviors[0])
		}
		if len(report.ThreatIntel.CapabilityNotes) > 0 {
			fmt.Fprintf(&b, "- 能力说明：%s\n", report.ThreatIntel.CapabilityNotes[0])
		}
	}

	fmt.Fprintf(&b, "\n## 总览\n\n")
	fmt.Fprintf(&b, "- 已扫描用户：%d\n", len(report.Profiles))
	fmt.Fprintf(&b, "- 发现 Apifox 痕迹的用户：%d\n", totalProfilesWithApifox)
	fmt.Fprintf(&b, "- Apifox IOC 文件命中：%d\n", totalHits)
	fmt.Fprintf(&b, "- 需复审的命令历史命中：%d\n", totalHistoryHits)
	fmt.Fprintf(&b, "- 用户级持久化命中：%d\n", totalUserPersistenceFindings)
	fmt.Fprintf(&b, "- 系统级持久化命中：%d\n", len(report.SystemPersistenceFindings))
	fmt.Fprintf(&b, "- Windows 注册表启动项命中：%d\n", len(report.WindowsArtifacts.RegistryAutoruns))
	fmt.Fprintf(&b, "- Windows Prefetch 命中：%d\n", len(report.WindowsArtifacts.PrefetchHits))
	fmt.Fprintf(&b, "- 人工复审项总数：%d\n", countManualReviewItems(report))
	fmt.Fprintf(&b, "- 当前运行中的 Apifox 进程：%d\n", len(report.Processes))

	sort.Slice(report.Profiles, func(i, j int) bool {
		return report.Profiles[i].Username < report.Profiles[j].Username
	})
	for _, profile := range report.Profiles {
		profileCompromiseText := profile.Assessment.CompromiseStatusText
		if profileCompromiseText == "" {
			profileCompromiseText = compromiseStatusCN(profile.Assessment.CompromiseStatus)
		}
		profileLabelText := profile.Assessment.LabelText
		if profileLabelText == "" {
			profileLabelText = assessmentLabelCN(profile.Assessment.Label)
		}
		fmt.Fprintf(&b, "\n## 用户 `%s`\n\n", profile.Username)
		fmt.Fprintf(&b, "- 中招判断：`%s`\n", profileCompromiseText)
		fmt.Fprintf(&b, "- 技术结论：`%s`\n", profileLabelText)
		if profile.Home != "" {
			fmt.Fprintf(&b, "- 主目录：`%s`\n", profile.Home)
		}
		for _, reason := range profile.Assessment.Reasons {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
		if len(profile.ApifoxHits) > 0 {
			limit := min(len(profile.ApifoxHits), 5)
			for i := 0; i < limit; i++ {
				hit := profile.ApifoxHits[i]
				fmt.Fprintf(&b, "- IOC 命中：`%s` [%s] 复审=`%s/%s`\n", hit.Path, strings.Join(hit.MatchedTokens, ", "), reviewStandardCN(hit.Review.Standard), hit.Review.Confidence)
			}
		}
		if len(profile.CommandHistoryHits) > 0 {
			limit := min(len(profile.CommandHistoryHits), 3)
			for i := 0; i < limit; i++ {
				hit := profile.CommandHistoryHits[i]
				summary := strings.Join(hit.Reasons, "; ")
				if len(hit.MatchedTokens) > 0 {
					summary = strings.Join(hit.MatchedTokens, ", ")
				}
				fmt.Fprintf(&b, "- 命令历史：`%s:%d` [%s] 复审=`%s/%s`\n", hit.Path, hit.LineNumber, summary, reviewStandardCN(hit.Review.Standard), hit.Review.Confidence)
			}
		}
		if len(profile.PersistenceFindings) > 0 {
			limit := min(len(profile.PersistenceFindings), 3)
			for i := 0; i < limit; i++ {
				finding := profile.PersistenceFindings[i]
				markerSummary := strings.Join(finding.Reasons, "; ")
				if len(finding.MatchedTokens) > 0 {
					markerSummary = strings.Join(finding.MatchedTokens, ", ")
				}
				fmt.Fprintf(&b, "- 持久化：`%s` [%s] 复审=`%s/%s`\n", finding.Path, markerSummary, reviewStandardCN(finding.Review.Standard), finding.Review.Confidence)
			}
		}
		exposedCount := 0
		for _, artifact := range profile.SensitiveArtifacts {
			if artifact.Exists {
				exposedCount++
			}
		}
		fmt.Fprintf(&b, "- 存在的敏感路径：%d/%d\n", exposedCount, len(profile.SensitiveArtifacts))
	}

	if len(report.SystemPersistenceFindings) > 0 {
		fmt.Fprintf(&b, "\n## 系统级持久化命中\n\n")
		limit := min(len(report.SystemPersistenceFindings), 3)
		for i := 0; i < limit; i++ {
			finding := report.SystemPersistenceFindings[i]
			markerSummary := strings.Join(finding.Reasons, "; ")
			if len(finding.MatchedTokens) > 0 {
				markerSummary = strings.Join(finding.MatchedTokens, ", ")
			}
			fmt.Fprintf(&b, "- `%s` [%s] 复审=`%s/%s`\n", finding.Path, markerSummary, reviewStandardCN(finding.Review.Standard), finding.Review.Confidence)
		}
	}

	if len(report.WindowsArtifacts.RegistryAutoruns) > 0 {
		fmt.Fprintf(&b, "\n## Windows 注册表启动项\n\n")
		limit := min(len(report.WindowsArtifacts.RegistryAutoruns), 3)
		for i := 0; i < limit; i++ {
			entry := report.WindowsArtifacts.RegistryAutoruns[i]
			summary := strings.Join(entry.Reasons, "; ")
			if len(entry.MatchedTokens) > 0 {
				summary = strings.Join(entry.MatchedTokens, ", ")
			}
			fmt.Fprintf(&b, "- `%s\\%s` [%s] 复审=`%s/%s`\n", entry.Key, entry.ValueName, summary, reviewStandardCN(entry.Review.Standard), entry.Review.Confidence)
		}
	}

	if len(report.WindowsArtifacts.PrefetchHits) > 0 {
		fmt.Fprintf(&b, "\n## Windows Prefetch 命中\n\n")
		limit := min(len(report.WindowsArtifacts.PrefetchHits), 3)
		for i := 0; i < limit; i++ {
			hit := report.WindowsArtifacts.PrefetchHits[i]
			fmt.Fprintf(&b, "- `%s` [%s] 复审=`%s/%s`\n", hit.Path, strings.Join(hit.Reasons, "; "), reviewStandardCN(hit.Review.Standard), hit.Review.Confidence)
		}
	}

	if len(report.ExtraRootFindings) > 0 {
		fmt.Fprintf(&b, "\n## 额外扫描目录\n\n")
		if extraRootMode(report.ExtraRootMode) == "external" {
			fmt.Fprintf(&b, "> 这些目录按外部证据处理：命中不会并入当前主机的中招结论或本机凭证泄露推断。\n\n")
		}
		for _, finding := range report.ExtraRootFindings {
			fmt.Fprintf(&b, "- `%s`：%d 个命中\n", finding.Root, len(finding.Hits))
		}
	}

	if report.C2ContactEvidence.ContactConfirmed || len(report.C2ContactEvidence.DNSCacheHits) > 0 ||
		len(report.C2ContactEvidence.ActiveConnections) > 0 || len(report.C2ContactEvidence.ElectronNetworkHits) > 0 {
		fmt.Fprintf(&b, "\n## C2 通信证据（是否被远程控制）\n\n")
		if report.C2ContactEvidence.ContactNote != "" {
			fmt.Fprintf(&b, "> %s\n\n", report.C2ContactEvidence.ContactNote)
		}
		if len(report.C2ContactEvidence.DNSCacheHits) > 0 {
			fmt.Fprintf(&b, "**DNS 缓存命中**（确认曾解析 C2 域名）：\n\n")
			for _, h := range report.C2ContactEvidence.DNSCacheHits {
				fmt.Fprintf(&b, "- `%s`\n", h)
			}
			fmt.Fprintf(&b, "\n")
		}
		if len(report.C2ContactEvidence.ActiveConnections) > 0 {
			fmt.Fprintf(&b, "**⚠️ 当前活跃 C2 连接**（进程仍在通信）：\n\n")
			for _, c := range report.C2ContactEvidence.ActiveConnections {
				fmt.Fprintf(&b, "- `%s`\n", c)
			}
			fmt.Fprintf(&b, "\n")
		}
		if len(report.C2ContactEvidence.ElectronNetworkHits) > 0 {
			fmt.Fprintf(&b, "**Electron Network 缓存命中**（历史请求残留）：\n\n")
			for _, h := range report.C2ContactEvidence.ElectronNetworkHits {
				fmt.Fprintf(&b, "- `%s` [%s]\n", h.Path, strings.Join(h.MatchedTokens, ", "))
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	if len(report.LeakageAnalysis.ExposedTypes) > 0 || report.LeakageAnalysis.RiskSummary != "" {
		fmt.Fprintf(&b, "\n## 泄露内容推断\n\n")
		if report.LeakageAnalysis.RiskSummary != "" {
			fmt.Fprintf(&b, "> %s\n\n", report.LeakageAnalysis.RiskSummary)
		}
		if report.LeakageAnalysis.PostExploitationRisk {
			fmt.Fprintf(&b, "> ⚠️ **二阶段深度利用风险**：%s\n\n", report.LeakageAnalysis.PostExploitationNote)
		}
		for _, ct := range report.LeakageAnalysis.ExposedTypes {
			fmt.Fprintf(&b, "### %s（%s / 风险：%s）\n\n", ct.Label, ct.Kind, riskLevelCN(ct.RiskLevel))
			fmt.Fprintf(&b, "- 证据：%s\n", ct.Evidence)
			fmt.Fprintf(&b, "- 必要处置：**%s**\n\n", ct.ActionRequired)
		}
	}

	if len(report.Recommendations) > 0 {
		fmt.Fprintf(&b, "\n## 建议的下一步\n\n")
		for _, step := range report.Recommendations {
			fmt.Fprintf(&b, "- %s\n", step)
		}
	}

	if len(report.Errors) > 0 {
		fmt.Fprintf(&b, "\n## 警告\n\n")
		for _, msg := range report.Errors {
			fmt.Fprintf(&b, "- %s\n", msg)
		}
	}

	return strings.TrimSpace(b.String())
}

func hasExistingApifoxDir(dirs []DirectoryStatus) bool {
	for _, dir := range dirs {
		if dir.Exists {
			return true
		}
	}
	return false
}

func riskLevelCN(level string) string {
	switch level {
	case "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	default:
		return level
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func extraRootMode(mode string) string {
	normalized, err := NormalizeExtraRootMode(mode)
	if err != nil {
		return "external"
	}
	return normalized
}
