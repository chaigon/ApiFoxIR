package triage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const maxFilesPerPersistenceRoot = 3000

type persistenceTarget struct {
	Path  string
	Kind  string
	Scope string
}

var suspiciousPersistenceExtensions = map[string]bool{
	".bat":     true,
	".cmd":     true,
	".command": true,
	".desktop": true,
	".dll":     true,
	".exe":     true,
	".hta":     true,
	".js":      true,
	".jse":     true,
	".plist":   true,
	".ps1":     true,
	".psm1":    true,
	".py":      true,
	".service": true,
	".sh":      true,
	".vbe":     true,
	".vbs":     true,
}

var suspiciousCommandMarkers = []string{
	"powershell",
	"cmd.exe",
	"mshta",
	"rundll32",
	"curl ",
	"wget ",
	"/bin/sh",
	"/bin/bash",
	"osascript",
	"python",
	"node ",
	"nohup ",
}

func scanUserPersistence(home string, cfg Config) ([]PersistenceLocation, []PersistenceFinding, []string) {
	return scanPersistenceTargets(discoverUserPersistenceTargets(home), cfg)
}

func scanSystemPersistence(cfg Config) ([]PersistenceLocation, []PersistenceFinding, []string) {
	return scanPersistenceTargets(discoverSystemPersistenceTargets(), cfg)
}

func discoverUserPersistenceTargets(home string) []persistenceTarget {
	var targets []persistenceTarget
	add := func(path, kind string) {
		targets = append(targets, persistenceTarget{
			Path:  filepath.Clean(path),
			Kind:  kind,
			Scope: "user",
		})
	}

	switch runtime.GOOS {
	case "windows":
		add(filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), "startup-folder")
	case "darwin":
		add(filepath.Join(home, "Library", "LaunchAgents"), "launch-agent")
	case "linux":
		add(filepath.Join(home, ".config", "autostart"), "autostart-desktop")
		add(filepath.Join(home, ".config", "systemd", "user"), "systemd-user")
	}

	return dedupePersistenceTargets(targets)
}

func discoverSystemPersistenceTargets() []persistenceTarget {
	var targets []persistenceTarget
	add := func(path, kind string) {
		targets = append(targets, persistenceTarget{
			Path:  filepath.Clean(path),
			Kind:  kind,
			Scope: "system",
		})
	}

	switch runtime.GOOS {
	case "windows":
		add(filepath.Join(`C:\ProgramData`, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), "startup-folder")
		add(filepath.Join(`C:\Windows`, "System32", "Tasks"), "scheduled-task")
	case "darwin":
		add("/Library/LaunchAgents", "launch-agent")
		add("/Library/LaunchDaemons", "launch-daemon")
	case "linux":
		add("/etc/systemd/system", "systemd-system")
		add("/etc/cron.d", "cron")
		add("/etc/cron.daily", "cron")
		add("/etc/init.d", "init-script")
	}

	return dedupePersistenceTargets(targets)
}

func dedupePersistenceTargets(targets []persistenceTarget) []persistenceTarget {
	seen := map[string]bool{}
	var deduped []persistenceTarget
	for _, target := range targets {
		if target.Path == "" || seen[target.Path] {
			continue
		}
		seen[target.Path] = true
		deduped = append(deduped, target)
	}
	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].Path < deduped[j].Path
	})
	return deduped
}

func scanPersistenceTargets(targets []persistenceTarget, cfg Config) ([]PersistenceLocation, []PersistenceFinding, []string) {
	var (
		locations []PersistenceLocation
		findings  []PersistenceFinding
		errs      []string
	)

	for _, target := range targets {
		location := PersistenceLocation{
			Path:  target.Path,
			Kind:  target.Kind,
			Scope: target.Scope,
		}

		info, err := os.Stat(target.Path)
		if err != nil {
			locations = append(locations, location)
			continue
		}
		location.Exists = true

		if info.IsDir() {
			rootFindings, latest, rootErrs := scanPersistenceRoot(target, cfg)
			location.LatestMTime = latest
			findings = append(findings, rootFindings...)
			errs = append(errs, rootErrs...)
			locations = append(locations, location)
			continue
		}

		location.LatestMTime = info.ModTime().UTC()
		locations = append(locations, location)
		finding, matched, inspectErr := inspectPersistenceFile(target, target.Path, info, cfg)
		if inspectErr != nil {
			errs = append(errs, fmt.Sprintf("持久化扫描失败 %s：%v", target.Path, inspectErr))
			continue
		}
		if matched {
			findings = append(findings, finding)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if len(findings[i].MatchedTokens) == len(findings[j].MatchedTokens) {
			return findings[i].Path < findings[j].Path
		}
		return len(findings[i].MatchedTokens) > len(findings[j].MatchedTokens)
	})
	return locations, findings, errs
}

func scanPersistenceRoot(target persistenceTarget, cfg Config) ([]PersistenceFinding, time.Time, []string) {
	var (
		findings    []PersistenceFinding
		errs        []string
		latestMTime time.Time
		filesSeen   int
	)

	_ = filepath.WalkDir(target.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Sprintf("遍历目录失败 %s：%v", path, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filesSeen >= maxFilesPerPersistenceRoot {
			errs = append(errs, fmt.Sprintf("持久化扫描在 %s 下扫描到 %d 个文件后被截断", target.Path, maxFilesPerPersistenceRoot))
			return errors.New("stop")
		}
		filesSeen++

		info, statErr := d.Info()
		if statErr != nil {
			errs = append(errs, fmt.Sprintf("读取文件信息失败 %s：%v", path, statErr))
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.ModTime().After(latestMTime) {
			latestMTime = info.ModTime().UTC()
		}

		finding, matched, inspectErr := inspectPersistenceFile(target, path, info, cfg)
		if inspectErr != nil {
			errs = append(errs, fmt.Sprintf("持久化扫描失败 %s：%v", path, inspectErr))
			return nil
		}
		if matched {
			findings = append(findings, finding)
		}
		return nil
	})

	return findings, latestMTime, errs
}

func inspectPersistenceFile(target persistenceTarget, path string, info fs.FileInfo, cfg Config) (PersistenceFinding, bool, error) {
	var data []byte
	if info.Size() > 0 && info.Size() <= cfg.MaxFileSize {
		readData, err := os.ReadFile(path)
		if err != nil {
			return PersistenceFinding{}, false, err
		}
		data = readData
	}

	mtime := info.ModTime().UTC()
	reasons := []string{}
	markers := []string{}
	matchedTokens := []string{}

	if len(data) > 0 {
		tokens, _ := matchIOCPatterns(strings.ToLower(string(data)))
		if len(tokens) > 0 {
			matchedTokens = append(matchedTokens, tokens...)
			reasons = append(reasons, "持久化位置中的文件内容直接包含事件 IOC")
		}
		markers = append(markers, findSuspiciousCommandMarkers(strings.ToLower(string(data)))...)
	}

	if strings.Contains(strings.ToLower(filepath.Base(path)), "apifox") {
		reasons = append(reasons, "持久化项名称直接引用了 apifox")
	}

	ext := strings.ToLower(filepath.Ext(path))
	if inIncidentWindow(mtime, cfg.IncidentStart, cfg.IncidentEnd) {
		if len(markers) > 0 {
			reasons = append(reasons, "持久化项在攻击窗口内引用了解释器、脚本执行器或下载器")
		}
		if suspiciousPersistenceExtensions[ext] {
			reasons = append(reasons, fmt.Sprintf("%s 中扩展名为 %s 的条目在攻击窗口内发生过改动", target.Kind, ext))
		}
	}

	if len(reasons) == 0 {
		return PersistenceFinding{}, false, nil
	}

	reasons = dedupeStrings(reasons)
	markers = dedupeStrings(markers)
	matchedTokens = dedupeStrings(matchedTokens)
	standard := "behavioral_correlation"
	why := "该持久化证据同时命中了启动行为、时间窗口、扩展名或解释器等可疑特征，需要人工判断其是否属于正常软件。"
	if len(matchedTokens) > 0 || strings.Contains(strings.ToLower(filepath.Base(path)), "apifox") {
		standard = "direct_ioc"
		why = "该持久化证据直接引用了事件 IOC 或 Apifox，应按高优先级复审。"
	}

	finding := PersistenceFinding{
		Path:          path,
		Kind:          target.Kind,
		Scope:         target.Scope,
		Size:          info.Size(),
		ModifiedAt:    mtime,
		MatchedTokens: matchedTokens,
		Markers:       markers,
		Reasons:       reasons,
		Review:        reviewGuidance(standard, why),
	}
	if info.Size() > 0 && info.Size() <= cfg.MaxFileSize {
		hash, err := fileSHA256(path)
		if err == nil {
			finding.SHA256 = hash
		}
	}
	return finding, true, nil
}

func findSuspiciousCommandMarkers(content string) []string {
	var markers []string
	for _, marker := range suspiciousCommandMarkers {
		if strings.Contains(content, marker) {
			markers = append(markers, strings.TrimSpace(marker))
		}
	}
	return markers
}
