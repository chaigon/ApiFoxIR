package triage

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var (
	registryValueLinePattern = regexp.MustCompile(`^\s{2,}(.+?)\s{2,}(REG_[A-Z0-9_]+)\s{2,}(.*)$`)
	registryUserSIDPattern   = regexp.MustCompile(`^HKEY_USERS\\S-\d-\d+(?:-\d+){1,14}$`)
)

var suspiciousAutorunPathMarkers = []string{
	`\\appdata\\`,
	`\\programdata\\`,
	`\\users\\public\\`,
	`\\windows\\temp\\`,
	`\\temp\\`,
	`%appdata%`,
	`%localappdata%`,
	`%programdata%`,
	`%temp%`,
	`%tmp%`,
}

var interestingPrefetchPrefixes = []string{
	"APIFOX",
	"POWERSHELL",
	"CMD",
	"MSHTA",
	"WSCRIPT",
	"CSCRIPT",
	"RUNDLL32",
	"REGSVR32",
	"CERTUTIL",
	"BITSADMIN",
	"NODE",
}

func scanWindowsArtifacts(cfg Config) (WindowsArtifacts, []string) {
	if runtime.GOOS != "windows" {
		return WindowsArtifacts{}, nil
	}

	registryAutoruns, regErrs := scanWindowsRegistryAutoruns()
	prefetchHits, prefetchErrs := scanWindowsPrefetch(cfg)

	return WindowsArtifacts{
		RegistryAutoruns: registryAutoruns,
		PrefetchHits:     prefetchHits,
	}, append(regErrs, prefetchErrs...)
}

func scanWindowsRegistryAutoruns() ([]RegistryAutorun, []string) {
	baseKeys := []struct {
		key   string
		scope string
	}{
		{key: `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`, scope: "system"},
		{key: `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`, scope: "system"},
		{key: `HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, scope: "system"},
		{key: `HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, scope: "system"},
	}

	userKeys, userErrs := discoverWindowsUserRunKeys()
	for _, key := range userKeys {
		baseKeys = append(baseKeys, struct {
			key   string
			scope string
		}{key: key, scope: "user"})
	}

	var (
		findings []RegistryAutorun
		errs     []string
	)
	errs = append(errs, userErrs...)

	for _, key := range baseKeys {
		out, err := exec.Command("reg", "query", key.key).CombinedOutput()
		if err != nil {
			if len(out) > 0 && strings.Contains(strings.ToLower(string(out)), "unable to find") {
				continue
			}
			errs = append(errs, fmt.Sprintf("注册表查询失败 %s：%v", key.key, err))
			continue
		}

		findings = append(findings, parseRegistryQueryOutput(key.key, key.scope, string(out))...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if len(findings[i].MatchedTokens) == len(findings[j].MatchedTokens) {
			return findings[i].Key < findings[j].Key
		}
		return len(findings[i].MatchedTokens) > len(findings[j].MatchedTokens)
	})
	return findings, errs
}

func discoverWindowsUserRunKeys() ([]string, []string) {
	out, err := exec.Command("reg", "query", `HKEY_USERS`).CombinedOutput()
	if err != nil {
		return nil, []string{fmt.Sprintf("注册表查询失败 HKEY_USERS：%v", err)}
	}

	var keys []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !registryUserSIDPattern.MatchString(line) {
			continue
		}
		keys = append(keys,
			line+`\Software\Microsoft\Windows\CurrentVersion\Run`,
			line+`\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		)
	}
	sort.Strings(keys)
	return dedupeStrings(keys), nil
}

func parseRegistryQueryOutput(key, scope, output string) []RegistryAutorun {
	var findings []RegistryAutorun
	for _, line := range strings.Split(output, "\n") {
		matches := registryValueLinePattern.FindStringSubmatch(line)
		if len(matches) != 4 {
			continue
		}

		valueName := strings.TrimSpace(matches[1])
		valueType := strings.TrimSpace(matches[2])
		command := strings.TrimSpace(matches[3])
		lower := strings.ToLower(command)

		matchedTokens, _ := matchIOCPatterns(lower)
		markers := dedupeStrings(findSuspiciousCommandMarkers(lower))
		pathMarkers := dedupeStrings(findSuspiciousAutorunPathMarkers(lower))
		reasons := []string{}

		if len(matchedTokens) > 0 {
			reasons = append(reasons, "注册表自启动项中直接包含事件 IOC")
		}
		if strings.Contains(lower, "apifox") {
			reasons = append(reasons, "注册表自启动命令直接引用了 apifox")
		}
		if len(markers) > 0 && len(pathMarkers) > 0 {
			reasons = append(reasons, "注册表自启动项会从用户可写路径启动解释器或下载器")
		}
		if len(markers) > 0 && strings.Contains(lower, "http") {
			reasons = append(reasons, "注册表自启动项中存在带网络地址的解释器或下载器调用")
		}

		if len(reasons) == 0 {
			continue
		}

		standard := "behavioral_correlation"
		why := "该注册表自启动项展示出可疑命令模式，需结合软件来源和上下文人工确认。"
		if len(matchedTokens) > 0 || strings.Contains(lower, "apifox") {
			standard = "direct_ioc"
			why = "该注册表自启动项直接引用了事件 IOC 或 Apifox，应优先人工复审。"
		}

		findings = append(findings, RegistryAutorun{
			Key:           key,
			Scope:         scope,
			ValueName:     valueName,
			ValueType:     valueType,
			Command:       command,
			MatchedTokens: matchedTokens,
			Markers:       markers,
			PathMarkers:   pathMarkers,
			Reasons:       dedupeStrings(reasons),
			Review:        reviewGuidance(standard, why),
		})
	}
	return findings
}

func findSuspiciousAutorunPathMarkers(content string) []string {
	var markers []string
	for _, marker := range suspiciousAutorunPathMarkers {
		if strings.Contains(content, marker) {
			markers = append(markers, marker)
		}
	}
	return markers
}

func scanWindowsPrefetch(cfg Config) ([]PrefetchHit, []string) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	prefetchDir := filepath.Join(systemRoot, "Prefetch")
	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		return nil, []string{fmt.Sprintf("无法读取 Prefetch 目录：%s", prefetchDir)}
	}

	var hits []PrefetchHit
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToUpper(entry.Name())
		if !strings.HasSuffix(name, ".PF") {
			continue
		}
		if !hasInterestingPrefetchPrefix(name) {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			continue
		}
		modTime := info.ModTime().UTC()
		if !inIncidentWindow(modTime, cfg.IncidentStart, cfg.IncidentEnd) {
			continue
		}

		reasons := []string{fmt.Sprintf("该 Prefetch 项在已知攻击窗口内发生过更新（%s）", modTime.Format(time.DateOnly))}
		if strings.HasPrefix(name, "APIFOX") {
			reasons = append(reasons, "Prefetch 表明 Apifox 曾在攻击窗口内执行")
		} else {
			reasons = append(reasons, "Prefetch 表明脚本执行器或 LOLBin 曾在攻击窗口内执行")
		}
		hits = append(hits, PrefetchHit{
			Path:       filepath.Join(prefetchDir, entry.Name()),
			Name:       entry.Name(),
			ModifiedAt: modTime,
			Reasons:    reasons,
			Review:     reviewGuidance("execution_artifact", "Prefetch 只能证明执行时间，必须结合时间线、相邻执行证据和日志后才能判断是否恶意。"),
		})
	}

	sort.Slice(hits, func(i, j int) bool {
		return hits[i].ModifiedAt.After(hits[j].ModifiedAt)
	})
	return hits, nil
}

func hasInterestingPrefetchPrefix(name string) bool {
	for _, prefix := range interestingPrefetchPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
