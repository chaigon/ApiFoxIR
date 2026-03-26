package triage

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

var suspiciousHistoryPathMarkers = []string{
	"/tmp/",
	"/var/tmp/",
	"/users/shared/",
	`\\appdata\\`,
	`\\programdata\\`,
	`\\temp\\`,
	`\\users\\public\\`,
}

var suspiciousHistoryChains = []struct {
	marker string
	match  func(string) bool
}{
	{
		marker: "curl-pipe-shell",
		match: func(line string) bool {
			return strings.Contains(line, "curl ") && hasAnySubstring(line, "| sh", "| bash", "| zsh", "| node", "| python")
		},
	},
	{
		marker: "curl-pipe-node",
		// 与攻击链高度吻合：Stage-2 正是通过 curl apifox.it.com/.*.js | node 方式在历史中可能留痕
		match: func(line string) bool {
			return strings.Contains(line, "curl ") && strings.Contains(line, "| node")
		},
	},
	{
		marker: "wget-pipe-shell",
		match: func(line string) bool {
			return strings.Contains(line, "wget ") && hasAnySubstring(line, "| sh", "| bash", "| zsh", "| node", "| python")
		},
	},
	{
		marker: "node-eval-remote",
		// eval()/Function() 结合 require('https') 或 require('http') 在 shell 中直接执行是高危模式
		match: func(line string) bool {
			return strings.Contains(line, "node ") && hasAnySubstring(line, "eval(", "function(", "-e \"", "-e '")
		},
	},
	{
		marker: "powershell-encoded",
		match: func(line string) bool {
			return strings.Contains(line, "powershell") && hasAnySubstring(line, "-enc", "-encodedcommand", "downloadstring", "invoke-expression", " iex ", "invoke-webrequest", " iwr ", " irm ")
		},
	},
	{
		marker: "mshta-network",
		match: func(line string) bool {
			return strings.Contains(line, "mshta") && hasAnySubstring(line, "http://", "https://")
		},
	},
	{
		marker: "bitsadmin-network",
		match: func(line string) bool {
			return strings.Contains(line, "bitsadmin") && hasAnySubstring(line, "http://", "https://")
		},
	},
	{
		marker: "certutil-download",
		match: func(line string) bool {
			return strings.Contains(line, "certutil") && hasAnySubstring(line, "urlcache", "http://", "https://")
		},
	},
	{
		marker: "chmod-run-tmp",
		match: func(line string) bool {
			return strings.Contains(line, "chmod +x") && containsAnyHistoryPathMarker(line)
		},
	},
	{
		marker: "ssh-new-host-key",
		// 攻击者用窃取的 SSH 私钥登录新主机后，known_hosts 新增记录；
		// 或受害者发现攻击者 IP 曾被 SSH 连接，此模式检测攻击窗口内对非常见主机的 ssh 操作
		match: func(line string) bool {
			return strings.Contains(line, "ssh ") && hasAnySubstring(line, "-i ~/.ssh/", "-i $home/.ssh/") &&
				hasAnySubstring(line, "apifox.it.com", "104.21.2.104", "172.67.129.21")
		},
	},
	{
		marker: "ps-aux-automated",
		// Stage-2 执行 ps aux 后若用户看到该命令出现在历史里（非交互输入）属于异常
		// 实际场景：攻击者后续阶段通过 shell 执行并留痕
		match: func(line string) bool {
			return (line == "ps aux" || line == "ps -aux" || line == "tasklist") &&
				!strings.Contains(line, "#")
		},
	},
	{
		marker: "aes-key-pattern",
		// AES 密钥硬编码：攻击者解密载荷后残留在历史中
		match: func(line string) bool {
			return hasAnySubstring(line, "foxapi", "scryptsync", "aes-256-gcm") &&
				hasAnySubstring(line, "node", "crypto", "decrypt")
		},
	},
}

type historyTarget struct {
	Path  string
	Shell string
}

func scanCommandHistory(home string, cfg Config) ([]CommandHistoryHit, []string) {
	var (
		hits []CommandHistoryHit
		errs []string
	)

	for _, target := range discoverHistoryTargets(home) {
		info, err := os.Stat(target.Path)
		if err != nil || info.IsDir() || info.Size() == 0 || info.Size() > cfg.MaxFileSize {
			continue
		}

		fileHits, scanErr := scanHistoryFile(target, cfg)
		if scanErr != nil {
			errs = append(errs, fmt.Sprintf("命令历史扫描失败 %s：%v", target.Path, scanErr))
			continue
		}
		hits = append(hits, fileHits...)
	}

	sort.Slice(hits, func(i, j int) bool {
		if len(hits[i].MatchedTokens) == len(hits[j].MatchedTokens) {
			if hits[i].Path == hits[j].Path {
				return hits[i].LineNumber < hits[j].LineNumber
			}
			return hits[i].Path < hits[j].Path
		}
		return len(hits[i].MatchedTokens) > len(hits[j].MatchedTokens)
	})
	return hits, errs
}

func discoverHistoryTargets(home string) []historyTarget {
	targets := []historyTarget{
		{Path: filepath.Join(home, ".bash_history"), Shell: "bash"},
		{Path: filepath.Join(home, ".zsh_history"), Shell: "zsh"},
		{Path: filepath.Join(home, ".config", "fish", "fish_history"), Shell: "fish"},
		{Path: filepath.Join(home, ".local", "share", "fish", "fish_history"), Shell: "fish"},
	}

	if runtime.GOOS == "windows" {
		targets = append(targets,
			historyTarget{
				Path:  filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
				Shell: "powershell",
			},
			historyTarget{
				Path:  filepath.Join(home, "AppData", "Roaming", "Microsoft", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
				Shell: "powershell",
			},
		)
	}

	return dedupeHistoryTargets(targets)
}

func dedupeHistoryTargets(targets []historyTarget) []historyTarget {
	seen := map[string]bool{}
	var deduped []historyTarget
	for _, target := range targets {
		cleaned := filepath.Clean(target.Path)
		if cleaned == "" || seen[cleaned] {
			continue
		}
		seen[cleaned] = true
		target.Path = cleaned
		deduped = append(deduped, target)
	}
	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].Path < deduped[j].Path
	})
	return deduped
}

func scanHistoryFile(target historyTarget, cfg Config) ([]CommandHistoryHit, error) {
	file, err := os.Open(target.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 0, 64*1024)
	scanner.Buffer(buffer, 1024*1024)

	var (
		hits       []CommandHistoryHit
		lineNumber int
	)
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		hit, matched := analyzeHistoryLine(target, lineNumber, line, cfg)
		if matched {
			hits = append(hits, hit)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hits, nil
}

func analyzeHistoryLine(target historyTarget, lineNumber int, line string, cfg Config) (CommandHistoryHit, bool) {
	lower := strings.ToLower(line)
	matchedTokens, _ := matchIOCPatterns(lower)
	markers := dedupeStrings(findSuspiciousHistoryChains(lower))
	reasons := []string{}

	if len(matchedTokens) > 0 {
		reasons = append(reasons, "命令历史内容直接包含事件 IOC")
	}
	if strings.Contains(lower, "apifox") {
		reasons = append(reasons, "命令历史直接引用了 apifox")
	}
	if len(markers) > 0 {
		reasons = append(reasons, "命令历史命中了高风险下载执行或编码执行模式")
	}

	if len(reasons) == 0 {
		return CommandHistoryHit{}, false
	}

	standard := "behavioral_correlation"
	why := "这条命令历史体现出高风险执行链，但仍需结合上下文判断它是正常运维还是恶意行为。"
	if len(matchedTokens) > 0 || strings.Contains(lower, "apifox") {
		standard = "direct_ioc"
		why = "这条命令历史直接引用了事件 IOC 或 Apifox，应优先复审其上下文和执行时间。"
	}

	return CommandHistoryHit{
		Path:          target.Path,
		Shell:         target.Shell,
		LineNumber:    lineNumber,
		MatchedTokens: matchedTokens,
		Markers:       markers,
		Reasons:       dedupeStrings(reasons),
		Review:        reviewGuidance(standard, why),
	}, true
}

func findSuspiciousHistoryPathMarkers(content string) []string {
	var markers []string
	for _, marker := range suspiciousHistoryPathMarkers {
		if strings.Contains(content, marker) {
			markers = append(markers, marker)
		}
	}
	return markers
}

func findSuspiciousHistoryChains(content string) []string {
	var markers []string
	for _, chain := range suspiciousHistoryChains {
		if chain.match(content) {
			markers = append(markers, chain.marker)
		}
	}
	return markers
}

func hasAnySubstring(value string, substrings ...string) bool {
	for _, substring := range substrings {
		if strings.Contains(value, substring) {
			return true
		}
	}
	return false
}

func containsAnyHistoryPathMarker(content string) bool {
	return len(findSuspiciousHistoryPathMarkers(content)) > 0
}
