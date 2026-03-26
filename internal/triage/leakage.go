package triage

// leakage.go — LevelDB 专项扫描、凭证内容分析、泄露推断
//
// 背景（基于 rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/）：
//   - Stage-1 将 _rl_headers/_rl_mc 写入 Apifox Electron 的 localStorage（底层 LevelDB）
//   - Stage-2 v1 窃取：~/.ssh/*、~/.zsh_history、~/.bash_history、~/.git-credentials、ps aux/tasklist
//   - Stage-2 v2 新增窃取：~/.kube/*、~/.zshrc、~/.npmrc、~/.subversion/*、目录树
//   - 攻击者持有 RSA 私钥，可解密所有外泄数据
//   - C2 eval() 平台可下发任意后续载荷，受影响用户不能排除深度入侵

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ── LevelDB 专项扫描 ──────────────────────────────────────────────────────────

// levelDBSubDirs 是 Electron 应用下存放 localStorage/LevelDB 数据的相对子路径集合。
var levelDBSubDirs = []string{
	"Local Storage/leveldb",
	"local storage/leveldb",
	"Default/Local Storage/leveldb",
}

// scanApifoxLevelDB 扫描 Apifox 数据目录中的 LevelDB 文件（.ldb / .log），
// 对其字节流做 IOC 字符串匹配，返回命中列表和错误列表。
// LevelDB 文件是二进制格式，但 IOC token 均为明文字符串，直接做 strings.Contains 即可覆盖绝大多数情形。
func scanApifoxLevelDB(apifoxDataDir string, maxFileSize int64, evidenceDir string) ([]FileHit, []string) {
	var (
		hits []FileHit
		errs []string
	)

	for _, sub := range levelDBSubDirs {
		ldbRoot := filepath.Join(apifoxDataDir, sub)
		info, err := os.Stat(ldbRoot)
		if err != nil || !info.IsDir() {
			continue
		}

		_ = filepath.WalkDir(ldbRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				errs = append(errs, fmt.Sprintf("LevelDB 目录遍历失败 %s：%v", path, walkErr))
				return nil
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext != ".ldb" && ext != ".log" {
				return nil
			}

			fi, statErr := d.Info()
			if statErr != nil {
				return nil
			}
			if fi.Size() == 0 || fi.Size() > maxFileSize {
				return nil
			}

			hit, matched, scanErr := scanFile(path, fi)
			if scanErr != nil {
				errs = append(errs, fmt.Sprintf("LevelDB 文件扫描失败 %s：%v", path, scanErr))
				return nil
			}
			if !matched {
				return nil
			}
			// 标注来源为 leveldb 以便报告区分
			hit.Review = reviewGuidance("direct_ioc",
				"该 LevelDB 文件直接包含事件 IOC（_rl_headers/_rl_mc 等恶意 localStorage 键），"+
					"这是恶意加载器在 Apifox 本地数据库中的直接写入痕迹，置信度极高。")

			if evidenceDir != "" {
				if rel, copyErr := copyEvidenceFile(path, evidenceDir); copyErr == nil {
					hit.CopiedEvidence = rel
				}
			}
			hits = append(hits, hit)
			return nil
		})
	}
	return hits, errs
}

// ── 凭证文件内容分析 ──────────────────────────────────────────────────────────

// analyzeCredentialFileContent 对单个凭证文件做内容摘要分析，
// 返回人类可读的发现描述列表（不输出明文凭证，仅说明存在何种敏感内容）。
func analyzeCredentialFileContent(name, path string, maxFileSize int64) []string {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() == 0 || info.Size() > maxFileSize {
		return nil
	}

	switch name {
	case "npm 凭证":
		return analyzeNpmrc(path)
	case "Git 凭证":
		return analyzeGitCredentials(path)
	case "zsh 配置", "bash 配置":
		return analyzeShellRC(path)
	}
	return nil
}

// analyzeNpmrc 检查 .npmrc 是否包含 registry token。
func analyzeNpmrc(path string) []string {
	var findings []string
	lines := readLines(path)
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if lower == "" || strings.HasPrefix(lower, "#") {
			continue
		}
		if strings.Contains(lower, "_authtoken") || strings.Contains(lower, "_auth=") {
			findings = append(findings, "发现 npm registry 认证 token（_authToken / _auth 字段存在）")
		}
		if strings.Contains(lower, "//registry.npmjs.org") || strings.Contains(lower, "//npm.pkg.github.com") {
			findings = append(findings, "发现指向 npmjs.org 或 GitHub Packages 的注册表凭证配置")
		}
		if strings.Contains(lower, "//") && strings.Contains(lower, "_authtoken") {
			findings = append(findings, "发现私有 registry 认证配置（攻击者可借此发布恶意包）")
		}
	}
	return dedupeStrings(findings)
}

// analyzeGitCredentials 检查 .git-credentials 内容格式。
func analyzeGitCredentials(path string) []string {
	var findings []string
	lines := readLines(path)
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if lower == "" {
			continue
		}
		if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
			if strings.Contains(lower, "@github.com") || strings.Contains(lower, "@gitlab") ||
				strings.Contains(lower, "@bitbucket") {
				findings = append(findings, "发现 Git 服务凭证（含 token 的 HTTPS URL 格式）：攻击者可直接 clone/push 关联仓库")
			} else {
				findings = append(findings, "发现 Git 凭证（HTTPS URL 格式含用户名/密码或 token）")
			}
		}
	}
	return dedupeStrings(findings)
}

// analyzeShellRC 检查 .zshrc / .bashrc 是否含内联敏感凭证。
func analyzeShellRC(path string) []string {
	var findings []string
	sensitivePatterns := []struct {
		keyword string
		desc    string
	}{
		{"aws_access_key_id", "AWS Access Key ID（export 变量）"},
		{"aws_secret_access_key", "AWS Secret Access Key（export 变量）"},
		{"database_url", "数据库连接字符串（DATABASE_URL 变量）"},
		{"db_password", "数据库密码（DB_PASSWORD 变量）"},
		{"api_key", "API Key 变量"},
		{"secret_key", "Secret Key 变量"},
		{"vault_token", "HashiCorp Vault Token 变量"},
		{"github_token", "GitHub Token 变量"},
		{"npm_token", "npm Token 变量"},
	}
	lines := readLines(path)
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if lower == "" || strings.HasPrefix(lower, "#") {
			continue
		}
		for _, pat := range sensitivePatterns {
			if strings.Contains(lower, pat.keyword) && (strings.Contains(lower, "export ") || strings.Contains(lower, "=")) {
				findings = append(findings, fmt.Sprintf("Shell 配置文件含内联敏感变量：%s（攻击者可通过 zsh_history 或 zshrc 窃取）", pat.desc))
			}
		}
	}
	return dedupeStrings(findings)
}

// readLines 读取文件所有行，失败时返回空。
func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

// ── 泄露推断引擎 ──────────────────────────────────────────────────────────────

// BuildLeakageAnalysis 根据扫描报告推断已泄露/风险凭证类型，生成 LeakageAnalysis。
// 调用时机：所有 profile 扫描完成后，assessment 生成前。
func BuildLeakageAnalysis(report *Report) LeakageAnalysis {
	var exposed []LeakedCredentialType
	includeExtraRoots := extraRootMode(report.ExtraRootMode) == "local"

	// 第一遍：先完整收集全机 Apifox 活动标志，再处理凭证。
	// 这样无论用户目录顺序如何，活动判断对所有 profile 都保持一致（修复 Bug 2）。
	hasApifoxActivity := false
	levelDBIOCFound := false
	for _, p := range report.Profiles {
		if p.ActivityDuringIncident {
			hasApifoxActivity = true
		}
		for _, hit := range p.ApifoxHits {
			for _, tok := range hit.MatchedTokens {
				if tok == "_rl_headers" || tok == "_rl_mc" {
					levelDBIOCFound = true
				}
			}
		}
	}
	// 只有把 -extra-root 明确声明为本机附加目录时，才把其中的 IOC 并入本机泄露推断。
	// 默认 external 模式下，这些目录只作为外部证据展示，避免把分析机本地凭证误判为已泄露。
	if includeExtraRoots {
		for _, ef := range report.ExtraRootFindings {
			for _, hit := range ef.Hits {
				hasApifoxActivity = true
				for _, tok := range hit.MatchedTokens {
					if tok == "_rl_headers" || tok == "_rl_mc" {
						levelDBIOCFound = true
					}
				}
			}
		}
	}

	// 没有任何 Apifox 活动或 IOC 证据时，跳过所有凭证推断，直接返回空结果（修复 Bug 1）。
	// 避免仅因本机存在常见敏感文件就误报"已泄露/需立即轮换"。
	if !hasApifoxActivity && !levelDBIOCFound {
		return LeakageAnalysis{
			RiskSummary: buildRiskSummary(report, 0, false, false),
		}
	}

	// 第二遍：基于已确认的活动标志，逐 profile 处理凭证文件
	for _, p := range report.Profiles {
		// 检查敏感路径并分析凭证内容
		for _, artifact := range p.SensitiveArtifacts {
			if !artifact.Exists {
				continue
			}
			switch artifact.Name {
			case "SSH 密钥":
				evidence := fmt.Sprintf("~/.ssh/ 目录存在，包含 %d 个文件（约 %d 字节）", artifact.FileCount, artifact.TotalSize)
				evidence += "；Apifox 在攻击窗口内有活动，Stage-2 v1 会递归读取该目录全部内容并外泄"
				exposed = append(exposed, LeakedCredentialType{
					Kind:           "ssh_private_key",
					Label:          "SSH 私钥",
					RiskLevel:      "high",
					Evidence:       evidence,
					ActionRequired: "立即废弃并轮换所有 ~/.ssh/ 下的密钥对；审查关联服务器的 authorized_keys 和登录日志，排查异常 SSH 登录",
				})
			case "Kubernetes 配置":
				evidence := fmt.Sprintf("~/.kube/ 目录存在，包含 %d 个文件", artifact.FileCount)
				evidence += "；Stage-2 v2 会外泄 ~/.kube/* 全部内容（含 OIDC token、集群 API 地址）"
				exposed = append(exposed, LeakedCredentialType{
					Kind:           "k8s_kubeconfig",
					Label:          "Kubernetes kubeconfig / OIDC Token",
					RiskLevel:      "high",
					Evidence:       evidence,
					ActionRequired: "立即轮换 kubeconfig 中的 OIDC refresh token；审查集群审计日志，排查非预期 API 调用；考虑重新颁发集群证书",
				})
			case "Git 凭证":
				evidence := fmt.Sprintf("~/.git-credentials 文件存在（%d 字节）", artifact.TotalSize)
				if len(artifact.CredentialFindings) > 0 {
					evidence += "；" + strings.Join(artifact.CredentialFindings, "，")
				}
				evidence += "；Stage-2 v1 明确窃取该文件，含明文 GitHub/GitLab PAT 或用户名密码"
				exposed = append(exposed, LeakedCredentialType{
					Kind:           "git_token",
					Label:          "Git Personal Access Token / 明文凭证",
					RiskLevel:      "high",
					Evidence:       evidence,
					ActionRequired: "立即在 GitHub/GitLab/Bitbucket 吊销所有 Personal Access Token；审查代码仓库提交历史和合作者，排查未授权访问或恶意 commit",
				})
			case "npm 凭证":
				evidence := fmt.Sprintf("~/.npmrc 文件存在（%d 字节）", artifact.TotalSize)
				if len(artifact.CredentialFindings) > 0 {
					// 有内容分析结果 + 已确认活动 → 高风险（修复 Bug 1：加活动门控）
					evidence += "；" + strings.Join(artifact.CredentialFindings, "，")
					evidence += "；Stage-2 v2 明确窃取该文件，可用于二次供应链攻击"
					exposed = append(exposed, LeakedCredentialType{
						Kind:           "npm_token",
						Label:          "npm Registry Token",
						RiskLevel:      "high",
						Evidence:       evidence,
						ActionRequired: "立即在 npmjs.org 或私有 registry 撤销 token；审查近期发布的 npm 包版本，确认未被植入恶意代码；如有私有 registry 也需同步撤销",
					})
				} else {
					// 无内容分析（文件存在但未检测到 token）→ 中风险
					evidence += "；Stage-2 v2 明确窃取该文件，含 registry token 时可用于二次供应链攻击"
					exposed = append(exposed, LeakedCredentialType{
						Kind:           "npm_token",
						Label:          "npm Registry Token（需确认）",
						RiskLevel:      "medium",
						Evidence:       evidence,
						ActionRequired: "检查 ~/.npmrc 是否含 _authToken；若存在则立即撤销并重新颁发",
					})
				}
			case "zsh 历史记录", "bash 历史记录":
				evidence := fmt.Sprintf("%s 存在（%d 字节）", artifact.Path, artifact.TotalSize)
				evidence += "；Stage-2 v1 完整读取命令历史，可能包含内联密码、API Key、数据库连接串、内部服务 URL"
				exposed = append(exposed, LeakedCredentialType{
					Kind:           "shell_history",
					Label:          "Shell 命令历史（含内联凭证）",
					RiskLevel:      "high",
					Evidence:       evidence,
					ActionRequired: "人工审查命令历史，找出内联密码/Token/API Key 并逐一轮换；清空历史记录前先备份作为取证材料",
				})
			case "zsh 配置":
				evidence := fmt.Sprintf("~/.zshrc 存在（%d 字节）", artifact.TotalSize)
				if len(artifact.CredentialFindings) > 0 {
					// 有内容分析结果 + 已确认活动 → 高风险（修复 Bug 1：加活动门控）
					evidence += "；发现内联敏感变量：" + strings.Join(artifact.CredentialFindings, "，")
					evidence += "；Stage-2 v2 明确读取该文件"
					exposed = append(exposed, LeakedCredentialType{
						Kind:           "shell_env_secret",
						Label:          "Shell 配置中的内联环境变量凭证",
						RiskLevel:      "high",
						Evidence:       evidence,
						ActionRequired: "立即轮换 .zshrc 中发现的所有 API Key / Token / 密码；后续改用 secret manager 或 .env 文件隔离凭证",
					})
				} else {
					// 无内容分析（文件存在但未检测到敏感变量）→ 中风险
					evidence += "；Stage-2 v2 明确读取该文件，可能暴露 export 语句中的 API Key/内部 URL/Vault Token"
					exposed = append(exposed, LeakedCredentialType{
						Kind:           "shell_env_secret",
						Label:          "Shell 配置暴露风险",
						RiskLevel:      "medium",
						Evidence:       evidence,
						ActionRequired: "人工检查 ~/.zshrc 中是否有 export 的明文凭证变量，若有则立即轮换",
					})
				}
			case "Subversion 认证/配置":
				exposed = append(exposed, LeakedCredentialType{
					Kind:           "svn_credentials",
					Label:          "Subversion 认证凭证",
					RiskLevel:      "medium",
					Evidence:       fmt.Sprintf("~/.subversion/ 目录存在，Stage-2 v2 明确读取该目录，可能含 SVN 明文密码"),
					ActionRequired: "在 SVN 服务端修改密码；审查 ~/.subversion/auth/ 目录内是否有明文存储的凭证文件",
				})
			}
		}
	}

	// 机器指纹（af_uuid）——MAC/CPU/主机名已外泄
	if hasApifoxActivity || levelDBIOCFound {
		exposed = append(exposed, LeakedCredentialType{
			Kind:           "machine_fingerprint",
			Label:          "机器指纹（MAC 地址、CPU、主机名、用户目录）",
			RiskLevel:      "medium",
			Evidence:       "Stage-1 恶意代码采集 MAC 地址 + CPU 型号 + 主机名 + 用户主目录并做 SHA-256 哈希，作为 af_uuid 上报给 C2",
			ActionRequired: "机器指纹无法轮换，但需记录在案；结合其他凭证泄露风险综合判断是否需要重装系统",
		})

		// Apifox 账户凭证
		exposed = append(exposed, LeakedCredentialType{
			Kind:           "apifox_account",
			Label:          "Apifox 账户邮箱和登录 Token",
			RiskLevel:      "medium",
			Evidence:       "Stage-1 从 localStorage 读取 common.accessToken，调用官方 API 获取用户邮箱和姓名后上报——攻击者持有账户邮箱，可用于定向钓鱼",
			ActionRequired: "修改 Apifox 账户密码并登出所有会话；检查账户内 API 项目数据是否被异常访问",
		})
	}

	// 进程列表
	if hasApifoxActivity || levelDBIOCFound {
		exposed = append(exposed, LeakedCredentialType{
			Kind:           "process_list",
			Label:          "完整进程列表（ps aux / tasklist）",
			RiskLevel:      "low",
			Evidence:       "Stage-2 v1 执行 ps aux（macOS/Linux）或 tasklist（Windows）并上报，攻击者可据此了解主机安装的安全工具和业务应用",
			ActionRequired: "该信息无法撤销；但可以据此推断攻击者已掌握本机软件栈，在评估后续钓鱼风险时应当考虑",
		})
	}

	// 构造摘要
	riskSummary := buildRiskSummary(report, len(exposed), hasApifoxActivity, levelDBIOCFound)

	postExploitationRisk := len(report.SystemPersistenceFindings) > 0 ||
		hasAnyProfilePersistence(report.Profiles) ||
		len(report.WindowsArtifacts.RegistryAutoruns) > 0

	postNote := ""
	if postExploitationRisk {
		postNote = "发现持久化证据，攻击者可能已通过 C2 eval() 平台下发后续载荷并在主机上独立驻留。" +
			"即使卸载 Apifox，后门仍可能继续运行。建议按整机受害处置，必要时重装系统。"
	} else if hasApifoxActivity || levelDBIOCFound {
		postExploitationRisk = true
		postNote = "C2 的 eval() 架构支持在任意一次 Apifox 运行周期内下发完全不同的后续载荷（横向移动、后门植入等）。" +
			"当前未发现独立持久化证据，但不能排除纯内存执行的后续阶段。攻击者可能已根据本机价值（SSH 密钥指向的服务器、K8s 集群规模）实施了定制化深度入侵。"
	}

	return LeakageAnalysis{
		ExposedTypes:         exposed,
		RiskSummary:          riskSummary,
		PostExploitationRisk: postExploitationRisk,
		PostExploitationNote: postNote,
	}
}

func buildRiskSummary(report *Report, exposedCount int, hasActivity, levelDBHit bool) string {
	if !hasActivity && !levelDBHit && exposedCount == 0 {
		return "当前扫描范围内未发现 Apifox 攻击窗口活动迹象，无法推断凭证泄露。如 Apifox 安装在非标准路径，请用 -extra-root 补扫。"
	}
	if levelDBHit {
		return fmt.Sprintf(
			"在 Apifox LevelDB 中发现恶意 localStorage 键（_rl_headers/_rl_mc），"+
				"确认恶意加载器已在本机执行。共推断出 %d 类已暴露凭证/数据，攻击者持有 RSA 私钥可解密全部外泄内容。",
			exposedCount,
		)
	}
	if hasActivity {
		return fmt.Sprintf(
			"Apifox 在攻击窗口（%s ~ %s）内存在活动痕迹，结合敏感文件存在情况，"+
				"推断 %d 类凭证/数据存在被窃取风险。即便未发现 IOC 残留，也不能排除恶意代码已执行并清理了自身痕迹。",
			report.IncidentStart.Format("2006-01-02"),
			report.IncidentEnd.Format("2006-01-02"),
			exposedCount,
		)
	}
	return fmt.Sprintf("基于敏感文件存在情况推断存在 %d 类潜在暴露风险，但未发现明确 Apifox 活动迹象。", exposedCount)
}

// ── C2 通信证据检测 ───────────────────────────────────────────────────────────

// BuildC2ContactEvidence 收集"主机是否曾主动联系 C2"的直接证据：
//  1. 查询 DNS 缓存（macOS: dscacheutil，Linux: /etc/hosts 不能用，依赖 nscd；Windows: ipconfig /displaydns）
//  2. 检查当前网络连接中是否有对 C2 IP 的活跃连接（lsof -i / netstat）
//  3. 扫描 Apifox Electron Network 缓存目录中的 IOC
func BuildC2ContactEvidence(report *Report) C2ContactEvidence {
	ev := C2ContactEvidence{}
	includeExtraRoots := extraRootMode(report.ExtraRootMode) == "local"

	ev.DNSCacheHits = queryDNSCache()
	ev.ActiveConnections = queryActiveC2Connections()

	// 从各用户的 Apifox 目录扫描 Network/ 子目录
	// 注意：LevelDB 命中已在 BuildLeakageAnalysis 中通过 levelDBIOCFound 处理，
	// 此处只扫描 Network 缓存目录，不重复追加 LevelDB 结果（修复 Bug 3）。
	for _, p := range report.Profiles {
		for _, dir := range p.ApifoxDirs {
			if !dir.Exists {
				continue
			}
			netDir := filepath.Join(dir.Path, "Network")
			info, err := os.Stat(netDir)
			if err != nil || !info.IsDir() {
				continue
			}
			netHits, _, _ := scanNetworkCacheDir(netDir, 32<<20)
			ev.ElectronNetworkHits = append(ev.ElectronNetworkHits, netHits...)
		}
	}
	// 只有把 -extra-root 明确声明为本机附加目录时，才把其中的 Network 缓存并入本机 C2 通信证据。
	if includeExtraRoots {
		for _, ef := range report.ExtraRootFindings {
			netDir := filepath.Join(ef.Root, "Network")
			info, err := os.Stat(netDir)
			if err != nil || !info.IsDir() {
				continue
			}
			netHits, _, _ := scanNetworkCacheDir(netDir, 32<<20)
			ev.ElectronNetworkHits = append(ev.ElectronNetworkHits, netHits...)
		}
	}

	// 综合判断：DNS 缓存、活跃连接、Electron Network 缓存命中均视为已联系 C2（修复 Bug 4）。
	ev.ContactConfirmed = len(ev.DNSCacheHits) > 0 || len(ev.ActiveConnections) > 0 || len(ev.ElectronNetworkHits) > 0
	ev.ContactNote = buildC2ContactNote(ev)
	return ev
}

// queryDNSCache 查询本地 DNS 缓存，寻找 C2 域名解析记录。
// macOS 使用 dscacheutil，Windows 使用 ipconfig，Linux 通常无持久 DNS 缓存（跳过）。
func queryDNSCache() []string {
	var hits []string
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("dscacheutil", "-cachedump", "-entries", "Host").Output()
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			for _, ind := range c2Indicators {
				if strings.Contains(lower, strings.ToLower(ind)) {
					hits = append(hits, strings.TrimSpace(line))
				}
			}
		}
	case "windows":
		out, err := exec.Command("ipconfig", "/displaydns").Output()
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			for _, ind := range c2Indicators {
				if strings.Contains(lower, strings.ToLower(ind)) {
					hits = append(hits, strings.TrimSpace(line))
				}
			}
		}
	}
	return dedupeStrings(hits)
}

// queryActiveC2Connections 检查当前是否有对 C2 IP/域名的活跃网络连接。
// macOS/Linux 使用 lsof -i，Windows 使用 netstat -ano。
func queryActiveC2Connections() []string {
	var hits []string
	switch runtime.GOOS {
	case "darwin", "linux":
		out, err := exec.Command("lsof", "-i", "-n", "-P").Output()
		if err != nil {
			// lsof 需要权限，尝试 netstat 作为降级
			out, err = exec.Command("netstat", "-an").Output()
			if err != nil {
				return nil
			}
		}
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			for _, ind := range c2Indicators {
				if strings.Contains(lower, strings.ToLower(ind)) {
					hits = append(hits, strings.TrimSpace(line))
				}
			}
		}
	case "windows":
		out, err := exec.Command("netstat", "-ano").Output()
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			for _, ind := range c2Indicators {
				if strings.Contains(lower, strings.ToLower(ind)) {
					hits = append(hits, strings.TrimSpace(line))
				}
			}
		}
	}
	return dedupeStrings(hits)
}

// scanNetworkCacheDir 扫描 Electron Network 缓存目录中的 IOC，
// 该目录以 Chromium 格式存储历史网络请求，可能残留对 C2 的请求记录。
func scanNetworkCacheDir(netDir string, maxFileSize int64) ([]FileHit, time.Time, []string) {
	hits, latest, errs := scanDirectoryForIOCs(netDir, maxFileSize, "")
	// 标注来源为 electron-network，置信度与 direct_ioc 相同
	for i := range hits {
		hits[i].Review = reviewGuidance("direct_ioc",
			"该文件位于 Apifox Electron Network 缓存目录中，包含 C2 IOC 字符串，"+
				"表明 Apifox 曾向 C2 发起过 HTTP 请求——是恶意代码联网执行的直接证据。")
	}
	return hits, latest, errs
}

func buildC2ContactNote(ev C2ContactEvidence) string {
	if len(ev.ActiveConnections) > 0 {
		return fmt.Sprintf(
			"[极高置信度] 当前存在 %d 条对 C2 的活跃网络连接——恶意代码很可能仍在运行并与攻击者保持通信。"+
				"立即隔离主机，强制终止所有 Apifox 进程后再继续取证。",
			len(ev.ActiveConnections),
		)
	}
	if len(ev.DNSCacheHits) > 0 && len(ev.ElectronNetworkHits) > 0 {
		return fmt.Sprintf(
			"[高置信度] DNS 缓存（%d 条）和 Electron Network 缓存（%d 个文件）均发现 C2 痕迹，"+
				"确认恶意代码曾在本机联网执行并向 C2 回传数据。",
			len(ev.DNSCacheHits), len(ev.ElectronNetworkHits),
		)
	}
	if len(ev.DNSCacheHits) > 0 {
		return fmt.Sprintf(
			"[高置信度] DNS 缓存中发现 %d 条 C2 域名解析记录，确认本机曾解析攻击者域名——"+
				"结合 Apifox 攻击窗口内活动，可推断恶意代码已联网执行。",
			len(ev.DNSCacheHits),
		)
	}
	if len(ev.ElectronNetworkHits) > 0 {
		return fmt.Sprintf(
			"[中置信度] Electron Network 缓存中发现 %d 个含 C2 IOC 的文件，"+
				"表明 Apifox 曾发起过包含 C2 特征的 HTTP 请求。DNS 缓存已过期或被清除，无法二次确认。",
			len(ev.ElectronNetworkHits),
		)
	}
	return ""
}
