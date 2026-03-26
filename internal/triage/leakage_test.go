package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Bug 1 回归：无 Apifox 活动时不产生误报 ────────────────────────────────────

// npm token 存在，但无任何 Apifox 活动/IOC → ExposedTypes 必须为空。
func TestBuildLeakageAnalysisNoFalsePositiveForNpmTokenWithoutActivity(t *testing.T) {
	report := &Report{
		ExtraRootMode: "external",
		Profiles: []ProfileReport{
			{
				Username: "developer",
				SensitiveArtifacts: []SensitiveArtifact{
					{
						Name:               "npm 凭证",
						Exists:             true,
						TotalSize:          128,
						CredentialFindings: []string{"发现 npm registry 认证 token（_authToken / _auth 字段存在）"},
					},
				},
			},
		},
	}

	analysis := BuildLeakageAnalysis(report)
	if len(analysis.ExposedTypes) != 0 {
		t.Fatalf("Bug 1 (npm): expected no exposed types without Apifox activity, got %#v", analysis.ExposedTypes)
	}
	if !strings.Contains(analysis.RiskSummary, "未发现 Apifox 攻击窗口活动迹象") {
		t.Fatalf("Bug 1 (npm): unexpected risk summary: %s", analysis.RiskSummary)
	}
}

// zsh 配置含内联敏感变量，但无任何 Apifox 活动/IOC → ExposedTypes 必须为空。
func TestBuildLeakageAnalysisNoFalsePositiveForZshrcWithoutActivity(t *testing.T) {
	report := &Report{
		ExtraRootMode: "external",
		Profiles: []ProfileReport{
			{
				Username: "developer",
				SensitiveArtifacts: []SensitiveArtifact{
					{
						Name:               "zsh 配置",
						Exists:             true,
						TotalSize:          256,
						CredentialFindings: []string{"Shell 配置文件含内联敏感变量：AWS Access Key ID（export 变量）"},
					},
				},
			},
		},
	}

	analysis := BuildLeakageAnalysis(report)
	if len(analysis.ExposedTypes) != 0 {
		t.Fatalf("Bug 1 (zshrc): expected no exposed types without Apifox activity, got %#v", analysis.ExposedTypes)
	}
}

// ── Bug 2 回归：多用户主机下顺序无关性 ──────────────────────────────────────

// profiles[0] 有 SSH 密钥，profiles[1] 才有 ActivityDuringIncident。
// 修复前：profiles[0] 在活动标志累积之前就被处理，SSH 密钥不会进入 ExposedTypes。
// 修复后：两遍遍历，profiles[0] 的 SSH 密钥必须出现在推断结果中。
func TestBuildLeakageAnalysisMultiUserSensitiveFileBeforeActivity(t *testing.T) {
	report := &Report{
		ExtraRootMode: "external",
		Profiles: []ProfileReport{
			{
				Username: "user-with-keys",
				SensitiveArtifacts: []SensitiveArtifact{
					{Name: "SSH 密钥", Exists: true, FileCount: 2, TotalSize: 3000},
				},
				// 无活动，但全机第二个用户有活动
			},
			{
				Username:               "user-with-activity",
				ActivityDuringIncident: true,
				SensitiveArtifacts:     []SensitiveArtifact{},
			},
		},
	}

	analysis := BuildLeakageAnalysis(report)
	found := false
	for _, et := range analysis.ExposedTypes {
		if et.Kind == "ssh_private_key" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Bug 2: ssh_private_key from first profile should be inferred when second profile has activity; got %#v", analysis.ExposedTypes)
	}
}

// ── Bug 3 回归：LevelDB 命中不应混入 ElectronNetworkHits ─────────────────────

// profile 有 LevelDB IOC 命中（ApifoxHits），但无 Network/ 子目录。
// 修复前：scanApifoxLevelDB() 结果被追加进 ElectronNetworkHits。
// 修复后：ElectronNetworkHits 必须为空。
func TestBuildC2ContactEvidenceLevelDBHitsNotMixedIntoNetworkHits(t *testing.T) {
	// 构造一个真实存在的 Apifox 数据目录（只有 LevelDB，没有 Network/）
	apifoxDir := t.TempDir()
	ldbDir := filepath.Join(apifoxDir, "Local Storage", "leveldb")
	if err := os.MkdirAll(ldbDir, 0o755); err != nil {
		t.Fatalf("mkdir leveldb: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ldbDir, "000003.log"),
		[]byte("\x00\x01_rl_headers\x00apifox.it.com"), 0o644); err != nil {
		t.Fatalf("write ldb: %v", err)
	}

	report := &Report{
		Profiles: []ProfileReport{
			{
				Username: "victim",
				ApifoxDirs: []DirectoryStatus{
					{Path: apifoxDir, Exists: true},
				},
				// ApifoxHits 模拟已扫描到的 LevelDB 命中
				ApifoxHits: []FileHit{
					{Path: filepath.Join(ldbDir, "000003.log"), MatchedTokens: []string{"_rl_headers", "apifox.it.com"}},
				},
			},
		},
	}

	evidence := BuildC2ContactEvidence(report)
	if len(evidence.ElectronNetworkHits) != 0 {
		t.Fatalf("Bug 3: LevelDB hits must not appear in ElectronNetworkHits, got %#v", evidence.ElectronNetworkHits)
	}
}

// ── Bug 4 回归：仅 ElectronNetworkHits 时 ContactConfirmed 应为 true ─────────

// 有 Network 缓存命中但无 DNS 缓存/活跃连接。
// 修复前：ContactConfirmed = false，主机总评被低估。
// 修复后：ContactConfirmed = true。
func TestBuildC2ContactEvidenceNetworkHitsAloneConfirmContact(t *testing.T) {
	netDir := filepath.Join(t.TempDir(), "Network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatalf("mkdir network: %v", err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "data_0"),
		[]byte("GET https://apifox.it.com/event/0/log HTTP/1.1"), 0o644); err != nil {
		t.Fatalf("write network cache: %v", err)
	}

	apifoxDir := filepath.Dir(netDir) // Network/ 的上层即模拟 Apifox 数据目录
	report := &Report{
		Profiles: []ProfileReport{
			{
				Username: "victim",
				ApifoxDirs: []DirectoryStatus{
					{Path: apifoxDir, Exists: true},
				},
			},
		},
	}

	evidence := BuildC2ContactEvidence(report)
	if len(evidence.ElectronNetworkHits) == 0 {
		t.Fatal("Bug 4: expected ElectronNetworkHits to be populated")
	}
	if !evidence.ContactConfirmed {
		t.Fatal("Bug 4: ContactConfirmed must be true when ElectronNetworkHits is non-empty")
	}
}

func TestBuildLeakageAnalysisIgnoresExternalExtraRootHits(t *testing.T) {
	report := &Report{
		ExtraRootMode: "external",
		Profiles: []ProfileReport{
			{
				Username: "analyst",
				SensitiveArtifacts: []SensitiveArtifact{
					{Name: "SSH 密钥", Exists: true, FileCount: 3, TotalSize: 4096},
				},
			},
		},
		ExtraRootFindings: []ExtraRootFinding{
			{
				Root: "/mnt/evidence/apifox",
				Hits: []FileHit{
					{Path: "/mnt/evidence/apifox/000003.log", MatchedTokens: []string{"_rl_headers", "apifox.it.com"}},
				},
			},
		},
	}

	analysis := BuildLeakageAnalysis(report)
	if len(analysis.ExposedTypes) != 0 {
		t.Fatalf("expected no local leakage inference for external extra-root hits, got %#v", analysis.ExposedTypes)
	}
	if !strings.Contains(analysis.RiskSummary, "未发现 Apifox 攻击窗口活动迹象") {
		t.Fatalf("unexpected risk summary: %s", analysis.RiskSummary)
	}
}

func TestBuildLeakageAnalysisCountsLocalExtraRootHits(t *testing.T) {
	report := &Report{
		ExtraRootMode: "local",
		Profiles: []ProfileReport{
			{
				Username: "local-user",
				SensitiveArtifacts: []SensitiveArtifact{
					{Name: "SSH 密钥", Exists: true, FileCount: 3, TotalSize: 4096},
				},
			},
		},
		ExtraRootFindings: []ExtraRootFinding{
			{
				Root: "/portable/apifox",
				Hits: []FileHit{
					{Path: "/portable/apifox/000003.log", MatchedTokens: []string{"_rl_headers", "apifox.it.com"}},
				},
			},
		},
	}

	analysis := BuildLeakageAnalysis(report)
	if len(analysis.ExposedTypes) == 0 {
		t.Fatal("expected local extra-root hits to drive leakage inference")
	}
	if !strings.Contains(analysis.RiskSummary, "确认恶意加载器已在本机执行") {
		t.Fatalf("unexpected risk summary: %s", analysis.RiskSummary)
	}
}

func TestBuildC2ContactEvidenceIgnoresExternalExtraRootNetworkHits(t *testing.T) {
	root := t.TempDir()
	networkDir := filepath.Join(root, "Network")
	if err := os.MkdirAll(networkDir, 0o755); err != nil {
		t.Fatalf("mkdir network: %v", err)
	}
	if err := os.WriteFile(filepath.Join(networkDir, "data_0"), []byte("https://apifox.it.com/event/0/log"), 0o644); err != nil {
		t.Fatalf("write network hit: %v", err)
	}

	report := &Report{
		ExtraRootMode: "external",
		ExtraRootFindings: []ExtraRootFinding{
			{Root: root},
		},
	}

	evidence := BuildC2ContactEvidence(report)
	if len(evidence.ElectronNetworkHits) != 0 {
		t.Fatalf("expected external extra-root network hits to be ignored, got %#v", evidence.ElectronNetworkHits)
	}
}

func TestBuildC2ContactEvidenceCountsLocalExtraRootNetworkHits(t *testing.T) {
	root := t.TempDir()
	networkDir := filepath.Join(root, "Network")
	if err := os.MkdirAll(networkDir, 0o755); err != nil {
		t.Fatalf("mkdir network: %v", err)
	}
	if err := os.WriteFile(filepath.Join(networkDir, "data_0"), []byte("https://apifox.it.com/event/0/log"), 0o644); err != nil {
		t.Fatalf("write network hit: %v", err)
	}

	report := &Report{
		ExtraRootMode: "local",
		ExtraRootFindings: []ExtraRootFinding{
			{Root: root},
		},
	}

	evidence := BuildC2ContactEvidence(report)
	if len(evidence.ElectronNetworkHits) == 0 {
		t.Fatal("expected local extra-root network hits to be counted")
	}
}
