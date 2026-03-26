package triage

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	maxFilesPerWalk          = 12000
	maxFilesPerSensitivePath = 4000
)

type profile struct {
	Username string
	Home     string
}

type candidateDir struct {
	Path   string
	Source string
}

func Run(cfg Config) (*Report, error) {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 32 << 20
	}
	if cfg.IncidentStart.IsZero() {
		cfg.IncidentStart = DefaultIncidentStart
	}
	if cfg.IncidentEnd.IsZero() {
		cfg.IncidentEnd = DefaultIncidentEnd
	}

	host, err := collectHostInfo()
	if err != nil {
		return nil, err
	}

	report := &Report{
		GeneratedAt:     time.Now().UTC(),
		IncidentName:    "Apifox 2026 年 3 月供应链事件取证分诊",
		IncidentStart:   cfg.IncidentStart,
		IncidentEnd:     cfg.IncidentEnd,
		Host:            host,
		ThreatIntel:     defaultThreatIntel(),
		ReviewStandards: defaultReviewStandards(),
		ExtraRootMode:   extraRootMode(cfg.ExtraRootMode),
	}

	if cfg.CopyApifoxEvidence {
		report.EvidenceDir = filepath.Join(cfg.OutputDir, "evidence")
	}

	profiles, err := enumerateProfiles()
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, errors.New("未找到可扫描的用户目录")
	}

	for _, p := range profiles {
		profileReport, errs := scanProfile(p, cfg, report.EvidenceDir)
		report.Profiles = append(report.Profiles, profileReport)
		report.Errors = append(report.Errors, errs...)
	}

	systemLocations, systemFindings, systemErrs := scanSystemPersistence(cfg)
	report.SystemPersistenceLocations = systemLocations
	report.SystemPersistenceFindings = systemFindings
	report.Errors = append(report.Errors, systemErrs...)

	windowsArtifacts, windowsErrs := scanWindowsArtifacts(cfg)
	report.WindowsArtifacts = windowsArtifacts
	report.Errors = append(report.Errors, windowsErrs...)

	if len(cfg.ExtraRoots) > 0 {
		for _, root := range dedupeStrings(cfg.ExtraRoots) {
			finding, errs := scanExtraRoot(root, cfg, report.EvidenceDir)
			report.ExtraRootFindings = append(report.ExtraRootFindings, finding)
			report.Errors = append(report.Errors, errs...)
		}
	}

	report.Processes = runningApifoxProcesses()
	report.C2ContactEvidence = BuildC2ContactEvidence(report)
	report.LeakageAnalysis = BuildLeakageAnalysis(report)
	report.Assessment = summarizeHostAssessment(report)
	report.Recommendations = defaultRecommendations(report)

	return report, nil
}

func collectHostInfo() (HostInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return HostInfo{}, err
	}

	currentUser := "未知"
	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	}

	return HostInfo{
		Hostname:    hostname,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		CurrentUser: currentUser,
	}, nil
}

func enumerateProfiles() ([]profile, error) {
	currentHome, _ := os.UserHomeDir()
	seen := map[string]bool{}
	var profiles []profile

	addProfile := func(home string) {
		home = filepath.Clean(home)
		if home == "" || home == "." || seen[home] {
			return
		}
		info, err := os.Stat(home)
		if err != nil || !info.IsDir() {
			return
		}
		seen[home] = true
		profiles = append(profiles, profile{
			Username: filepath.Base(home),
			Home:     home,
		})
	}

	if currentHome != "" {
		addProfile(currentHome)
	}

	switch runtime.GOOS {
	case "windows":
		entries, err := os.ReadDir(`C:\Users`)
		if err != nil && len(profiles) == 0 {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := strings.ToLower(entry.Name())
			if name == "public" || strings.HasPrefix(name, "default") || name == "all users" {
				continue
			}
			addProfile(filepath.Join(`C:\Users`, entry.Name()))
		}
	case "darwin":
		entries, _ := os.ReadDir("/Users")
		for _, entry := range entries {
			name := strings.ToLower(entry.Name())
			if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && name != "shared" && name != "guest" {
				addProfile(filepath.Join("/Users", entry.Name()))
			}
		}
	case "linux":
		entries, _ := os.ReadDir("/home")
		for _, entry := range entries {
			if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
				addProfile(filepath.Join("/home", entry.Name()))
			}
		}
		addProfile("/root")
	}

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Home < profiles[j].Home
	})
	return profiles, nil
}

func scanProfile(p profile, cfg Config, evidenceDir string) (ProfileReport, []string) {
	var errs []string
	sensArtifacts := inspectSensitiveArtifacts(p.Home, cfg.MaxFileSize)
	// 对文件类型的敏感路径做内容分析
	for i := range sensArtifacts {
		if sensArtifacts[i].Exists && sensArtifacts[i].Kind == "file" {
			sensArtifacts[i].CredentialFindings = analyzeCredentialFileContent(
				sensArtifacts[i].Name, sensArtifacts[i].Path, cfg.MaxFileSize,
			)
		}
	}
	report := ProfileReport{
		Username:           p.Username,
		Home:               p.Home,
		SensitiveArtifacts: sensArtifacts,
	}

	commandHistoryHits, historyErrs := scanCommandHistory(p.Home, cfg)
	report.CommandHistoryHits = commandHistoryHits
	errs = append(errs, historyErrs...)

	candidates := discoverApifoxDirs(p.Home)
	for _, dir := range candidates {
		status := DirectoryStatus{
			Path:   dir.Path,
			Source: dir.Source,
		}
		info, err := os.Stat(dir.Path)
		if err != nil || !info.IsDir() {
			report.ApifoxDirs = append(report.ApifoxDirs, status)
			continue
		}

		status.Exists = true
		hits, latestMTime, scanErrs := scanDirectoryForIOCs(dir.Path, cfg.MaxFileSize, evidenceDir)
		status.LatestMTime = latestMTime
		if !latestMTime.IsZero() && inIncidentWindow(latestMTime, cfg.IncidentStart, cfg.IncidentEnd) {
			report.ActivityDuringIncident = true
		}
		report.ApifoxDirs = append(report.ApifoxDirs, status)
		report.ApifoxHits = append(report.ApifoxHits, hits...)
		errs = append(errs, scanErrs...)

		// LevelDB 专项扫描：直接解析 Apifox Local Storage/leveldb 目录
		ldbHits, ldbErrs := scanApifoxLevelDB(dir.Path, cfg.MaxFileSize, evidenceDir)
		report.ApifoxHits = append(report.ApifoxHits, ldbHits...)
		errs = append(errs, ldbErrs...)
	}

	persistenceLocations, persistenceFindings, persistenceErrs := scanUserPersistence(p.Home, cfg)
	report.PersistenceLocations = persistenceLocations
	report.PersistenceFindings = persistenceFindings
	errs = append(errs, persistenceErrs...)

	report.Assessment = summarizeProfileAssessment(report, cfg)
	report.Notes = profileNotes(report, cfg)
	sortHits(report.ApifoxHits)
	return report, errs
}

func discoverApifoxDirs(home string) []candidateDir {
	seen := map[string]bool{}
	var dirs []candidateDir
	add := func(path, source string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if seen[path] {
			return
		}
		seen[path] = true
		dirs = append(dirs, candidateDir{Path: path, Source: source})
	}

	switch runtime.GOOS {
	case "windows":
		add(filepath.Join(home, "AppData", "Roaming", "Apifox"), "standard-electron-user-data")
		add(filepath.Join(home, "AppData", "Local", "Apifox"), "standard-local-data")
		add(filepath.Join(home, "AppData", "Roaming"), "apifox-dir-discovery-root")
		add(filepath.Join(home, "AppData", "Local"), "apifox-dir-discovery-root")
	case "darwin":
		add(filepath.Join(home, "Library", "Application Support", "Apifox"), "standard-electron-user-data")
		add(filepath.Join(home, "Library", "Application Support"), "apifox-dir-discovery-root")
		add(filepath.Join(home, "Library", "Logs", "Apifox"), "log-root")
	case "linux":
		add(filepath.Join(home, ".config", "Apifox"), "standard-electron-user-data")
		add(filepath.Join(home, ".config"), "apifox-dir-discovery-root")
	}

	// Broad fallback for mixed or unusual installations.
	add(filepath.Join(home, ".config", "apifox"), "fallback-config-root")
	add(filepath.Join(home, ".local", "share", "Apifox"), "fallback-share-root")
	add(filepath.Join(home, "Library", "Application Support", "apifox"), "fallback-app-support-root")

	var expanded []candidateDir
	for _, dir := range dirs {
		expanded = append(expanded, dir)
		if strings.Contains(strings.ToLower(dir.Source), "discovery-root") {
			for _, discovered := range discoverNamedSubdirs(dir.Path, "apifox", 3) {
				expanded = append(expanded, candidateDir{Path: discovered, Source: "discovered-name-match"})
			}
		}
	}

	seen = map[string]bool{}
	var final []candidateDir
	for _, dir := range expanded {
		cleaned := filepath.Clean(dir.Path)
		if strings.Contains(strings.ToLower(dir.Source), "discovery-root") {
			continue
		}
		if seen[cleaned] {
			continue
		}
		seen[cleaned] = true
		final = append(final, candidateDir{Path: cleaned, Source: dir.Source})
	}
	sort.Slice(final, func(i, j int) bool {
		return final[i].Path < final[j].Path
	})
	return final
}

func discoverNamedSubdirs(root, needle string, maxDepth int) []string {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil
	}

	var matches []string
	root = filepath.Clean(root)
	baseDepth := strings.Count(root, string(os.PathSeparator))

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			return nil
		}
		if path == root {
			return nil
		}
		depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - baseDepth
		if depth > maxDepth {
			return filepath.SkipDir
		}
		if strings.Contains(strings.ToLower(d.Name()), strings.ToLower(needle)) {
			matches = append(matches, path)
		}
		return nil
	})
	return dedupeStrings(matches)
}

func inspectSensitiveArtifacts(home string, maxFileSize int64) []SensitiveArtifact {
	var artifacts []SensitiveArtifact
	for _, spec := range DefaultSensitiveSpecs {
		for _, rel := range spec.RelativePaths {
			path := filepath.Join(home, rel)
			artifacts = append(artifacts, inspectSensitivePath(spec.Name, spec.Kind, path, maxFileSize))
		}
	}
	return artifacts
}

func inspectSensitivePath(name, kind, path string, maxFileSize int64) SensitiveArtifact {
	artifact := SensitiveArtifact{
		Name: name,
		Kind: kind,
		Path: path,
	}

	info, err := os.Stat(path)
	if err != nil {
		return artifact
	}
	artifact.Exists = true
	artifact.ModifiedAt = info.ModTime().UTC()

	if kind == "directory" {
		fileCount, totalSize, truncated := summarizeDirectory(path, maxFilesPerSensitivePath)
		artifact.FileCount = fileCount
		artifact.TotalSize = totalSize
		artifact.Truncated = truncated
		return artifact
	}

	artifact.TotalSize = info.Size()
	if info.Size() <= maxFileSize {
		hash, err := fileSHA256(path)
		if err == nil {
			artifact.SHA256 = hash
		}
	}
	return artifact
}

func summarizeDirectory(root string, limit int) (int, int64, bool) {
	var (
		fileCount int
		totalSize int64
		truncated bool
	)

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if fileCount >= limit {
			truncated = true
			return errors.New("stop")
		}
		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}
		fileCount++
		totalSize += info.Size()
		return nil
	})
	return fileCount, totalSize, truncated
}

func scanExtraRoot(root string, cfg Config, evidenceDir string) (ExtraRootFinding, []string) {
	finding := ExtraRootFinding{Root: filepath.Clean(root)}
	info, err := os.Stat(finding.Root)
	if err != nil || !info.IsDir() {
		return finding, []string{fmt.Sprintf("额外扫描目录不可读：%s", finding.Root)}
	}
	hits, _, errs := scanDirectoryForIOCs(finding.Root, cfg.MaxFileSize, evidenceDir)
	sortHits(hits)
	finding.Hits = hits
	return finding, errs
}

func scanDirectoryForIOCs(root string, maxFileSize int64, evidenceDir string) ([]FileHit, time.Time, []string) {
	var (
		hits        []FileHit
		errs        []string
		latestMTime time.Time
		filesSeen   int
	)

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Sprintf("遍历目录失败 %s：%v", path, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filesSeen >= maxFilesPerWalk {
			errs = append(errs, fmt.Sprintf("扫描目录 %s 时在处理 %d 个文件后被截断", root, maxFilesPerWalk))
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
		if info.Size() == 0 || info.Size() > maxFileSize {
			return nil
		}

		hit, matched, matchErr := scanFile(path, info)
		if matchErr != nil {
			errs = append(errs, fmt.Sprintf("扫描文件失败 %s：%v", path, matchErr))
			return nil
		}
		if !matched {
			return nil
		}

		if evidenceDir != "" {
			relPath, copyErr := copyEvidenceFile(path, evidenceDir)
			if copyErr != nil {
				errs = append(errs, fmt.Sprintf("复制留证文件失败 %s：%v", path, copyErr))
			} else {
				hit.CopiedEvidence = relPath
			}
		}
		hits = append(hits, hit)
		return nil
	})

	return hits, latestMTime, errs
}

func scanFile(path string, info fs.FileInfo) (FileHit, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileHit{}, false, err
	}
	matchedTokens, categories := matchIOCPatterns(strings.ToLower(string(data)))
	if len(matchedTokens) == 0 {
		return FileHit{}, false, nil
	}

	hashBytes := sha256.Sum256(data)
	hit := FileHit{
		Path:          path,
		MatchedTokens: matchedTokens,
		Categories:    categories,
		Size:          info.Size(),
		SHA256:        hex.EncodeToString(hashBytes[:]),
		ModifiedAt:    info.ModTime().UTC(),
		Review:        reviewGuidance("direct_ioc", "该文件直接包含公开事件 IOC，应作为高优先级强信号进行复审。"),
	}
	return hit, true, nil
}

func matchIOCPatterns(content string) ([]string, []string) {
	matchedTokens := map[string]bool{}
	categorySet := map[string]bool{}
	for _, pattern := range DefaultIOCPatterns {
		if strings.Contains(content, pattern.Token) {
			matchedTokens[pattern.Token] = true
			categorySet[pattern.Category] = true
		}
	}

	var tokens []string
	for token := range matchedTokens {
		tokens = append(tokens, token)
	}
	var categories []string
	for category := range categorySet {
		categories = append(categories, category)
	}
	sort.Strings(tokens)
	sort.Strings(categories)
	return tokens, categories
}

func copyEvidenceFile(src, evidenceDir string) (string, error) {
	relative := sanitizeEvidencePath(src)
	dst := filepath.Join(evidenceDir, relative)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	return dst, nil
}

func sanitizeEvidencePath(path string) string {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if volume != "" {
		path = strings.TrimPrefix(path, volume)
		volume = strings.TrimSuffix(volume, ":")
		volume = strings.ReplaceAll(volume, string(os.PathSeparator), "_")
		return filepath.Join(volume, strings.TrimLeft(path, `\/`))
	}
	return strings.TrimLeft(path, string(os.PathSeparator))
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func runningApifoxProcesses() []ProcessInfo {
	switch runtime.GOOS {
	case "windows":
		return runningApifoxProcessesWindows()
	default:
		return runningApifoxProcessesUnix()
	}
}

func runningApifoxProcessesUnix() []ProcessInfo {
	out, err := exec.Command("ps", "-axo", "pid=,comm=").Output()
	if err != nil {
		return nil
	}

	var processes []ProcessInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		if strings.Contains(strings.ToLower(name), "apifox") {
			processes = append(processes, ProcessInfo{PID: fields[0], Name: name})
		}
	}
	return processes
}

func runningApifoxProcessesWindows() []ProcessInfo {
	out, err := exec.Command("tasklist", "/fo", "csv", "/nh").Output()
	if err != nil {
		return nil
	}

	reader := csv.NewReader(strings.NewReader(string(out)))
	rows, err := reader.ReadAll()
	if err != nil {
		return nil
	}

	var processes []ProcessInfo
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		name := row[0]
		if strings.Contains(strings.ToLower(name), "apifox") {
			processes = append(processes, ProcessInfo{PID: row[1], Name: name})
		}
	}
	return processes
}

func summarizeProfileAssessment(profile ProfileReport, cfg Config) Assessment {
	var reasons []string
	severity := "low"
	label := "no-clear-host-ioc"
	persistenceIOCFindings := countPersistenceIOCFindings(profile.PersistenceFindings)

	if len(profile.ApifoxHits) > 0 {
		severity = "high"
		label = "host-ioc-found"
		reasons = append(reasons, fmt.Sprintf("在 Apifox/Electron 数据目录下发现 %d 个包含事件 IOC 的文件", len(profile.ApifoxHits)))
	}

	if hasExistingApifoxDir(profile.ApifoxDirs) && profile.ActivityDuringIncident {
		reasons = append(reasons, fmt.Sprintf("Apifox 数据目录在 %s 到 %s 之间存在写入活动", cfg.IncidentStart.Format(time.DateOnly), cfg.IncidentEnd.Format(time.DateOnly)))
		if severity == "low" {
			severity = "medium"
			label = "likely-exposed-host"
		}
	}

	sensitiveCount := 0
	for _, artifact := range profile.SensitiveArtifacts {
		if artifact.Exists {
			sensitiveCount++
		}
	}
	if sensitiveCount > 0 {
		reasons = append(reasons, fmt.Sprintf("该用户目录中存在 %d 个被恶意代码明确针对的敏感凭证或历史记录路径", sensitiveCount))
		if severity == "low" && hasExistingApifoxDir(profile.ApifoxDirs) {
			severity = "medium"
			label = "credentials-at-risk"
		}
	}

	if len(profile.CommandHistoryHits) > 0 {
		if severity == "low" {
			severity = "medium"
			label = "manual-review-required"
		}
		reasons = append(reasons, fmt.Sprintf("发现 %d 条需要人工复审的命令历史记录", len(profile.CommandHistoryHits)))
	}

	if persistenceIOCFindings > 0 {
		severity = "high"
		label = "possible-post-exploitation"
		reasons = append(reasons, fmt.Sprintf("在 Apifox 数据目录之外发现 %d 个包含事件 IOC 的持久化证据", persistenceIOCFindings))
	} else if len(profile.PersistenceFindings) > 0 && (len(profile.ApifoxHits) > 0 || profile.ActivityDuringIncident) {
		if severity == "low" {
			severity = "medium"
		}
		label = "possible-post-exploitation"
		reasons = append(reasons, fmt.Sprintf("发现 %d 个在攻击窗口内改动过或带有事件特征的启动/自启动证据", len(profile.PersistenceFindings)))
	}

	if !hasExistingApifoxDir(profile.ApifoxDirs) && severity == "low" {
		label = "no-apifox-artifacts-found"
		reasons = append(reasons, "未发现该用户的 Apifox 用户数据目录")
	}

	return buildAssessment(severity, label, reasons)
}

func summarizeHostAssessment(report *Report) Assessment {
	hostAssessment := buildAssessment("low", "no-clear-host-ioc", []string{"在已扫描位置中未发现事件 IOC 字符串。"})

	var (
		totalHits                   int
		profilesWithIncidentUsage   int
		profilesWithSensitiveData   int
		totalPersistenceFindings    int
		totalPersistenceIOCFindings int
		registryIOCFindings         int
		registrySuspiciousFindings  int
		totalHistoryHits            int
	)
	for _, profile := range report.Profiles {
		totalHits += len(profile.ApifoxHits)
		totalPersistenceFindings += len(profile.PersistenceFindings)
		totalPersistenceIOCFindings += countPersistenceIOCFindings(profile.PersistenceFindings)
		totalHistoryHits += len(profile.CommandHistoryHits)
		if profile.ActivityDuringIncident {
			profilesWithIncidentUsage++
		}
		for _, artifact := range profile.SensitiveArtifacts {
			if artifact.Exists {
				profilesWithSensitiveData++
				break
			}
		}
	}
	if extraRootMode(report.ExtraRootMode) == "local" {
		for _, finding := range report.ExtraRootFindings {
			totalHits += len(finding.Hits)
		}
	}
	totalPersistenceFindings += len(report.SystemPersistenceFindings)
	totalPersistenceIOCFindings += countPersistenceIOCFindings(report.SystemPersistenceFindings)
	registryIOCFindings = countRegistryIOCFindings(report.WindowsArtifacts.RegistryAutoruns)
	registrySuspiciousFindings = len(report.WindowsArtifacts.RegistryAutoruns)

	switch {
	case len(report.C2ContactEvidence.ActiveConnections) > 0:
		hostAssessment.Severity = "high"
		hostAssessment.Label = "possible-post-exploitation"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("发现 %d 条对 C2（apifox.it.com / 104.21.2.104）的当前活跃网络连接，恶意代码很可能仍在运行", len(report.C2ContactEvidence.ActiveConnections)),
			"立即隔离主机，强制终止所有 Apifox 进程后再继续取证",
		}
	case report.C2ContactEvidence.ContactConfirmed:
		hostAssessment.Severity = "high"
		hostAssessment.Label = "host-ioc-found"
		hostAssessment.Reasons = []string{
			"DNS 缓存、活跃网络连接或 Electron Network 缓存中确认曾联系 C2（apifox.it.com），恶意代码已在本机联网执行",
		}
	case registryIOCFindings > 0:
		hostAssessment.Severity = "high"
		hostAssessment.Label = "possible-post-exploitation"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("发现 %d 个包含事件 IOC 或直接引用 Apifox 的注册表自启动项", registryIOCFindings),
			"这表明入侵行为可能已经脱离 Apifox 进程并建立持久化",
		}
	case totalPersistenceIOCFindings > 0:
		hostAssessment.Severity = "high"
		hostAssessment.Label = "possible-post-exploitation"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("发现 %d 个包含事件 IOC 的持久化证据", totalPersistenceIOCFindings),
			"这表明二阶段活动可能已经脱离 Apifox 进程，建议按整机受害进行处置",
		}
	case totalHits > 0:
		hostAssessment.Severity = "high"
		hostAssessment.Label = "host-ioc-found"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("在 Apifox 目录及额外扫描目录中共发现 %d 个命中 IOC 的文件", totalHits),
			"在没有相反证据前，这已足以将主机视为已受害",
		}
	case totalPersistenceFindings > 0 && profilesWithIncidentUsage > 0:
		hostAssessment.Severity = "medium"
		hostAssessment.Label = "possible-post-exploitation"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("发现 %d 个在攻击窗口内改动过或带有事件特征的启动/自启动证据", totalPersistenceFindings),
			fmt.Sprintf("同时有 %d 个用户在已知攻击窗口内存在 Apifox 使用痕迹", profilesWithIncidentUsage),
		}
	case registrySuspiciousFindings > 0 && profilesWithIncidentUsage > 0:
		hostAssessment.Severity = "medium"
		hostAssessment.Label = "possible-post-exploitation"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("发现 %d 个可疑注册表自启动项，且有 %d 个用户在攻击窗口内存在 Apifox 使用痕迹", registrySuspiciousFindings, profilesWithIncidentUsage),
			"由于注册表 Run 键是常见持久化位置，这类结果必须人工复核",
		}
	case totalHistoryHits > 0:
		hostAssessment.Severity = "medium"
		hostAssessment.Label = "manual-review-required"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("发现 %d 条需要人工复审的命令历史命中", totalHistoryHits),
			"命令历史既可能反映攻击者操作，也可能只是正常运维或开发活动，不能单独直接定性为入侵",
		}
	case profilesWithIncidentUsage > 0 && profilesWithSensitiveData > 0:
		hostAssessment.Severity = "medium"
		hostAssessment.Label = "likely-exposed-host"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("有 %d 个用户在已知攻击窗口内使用过 Apifox", profilesWithIncidentUsage),
			fmt.Sprintf("其中 %d 个用户目录还包含恶意代码明确针对的凭证路径", profilesWithSensitiveData),
		}
	case profilesWithIncidentUsage > 0:
		hostAssessment.Severity = "medium"
		hostAssessment.Label = "apifox-active-during-window"
		hostAssessment.Reasons = []string{
			fmt.Sprintf("有 %d 个用户在已知攻击窗口内存在 Apifox 数据活动", profilesWithIncidentUsage),
			"即便未发现残留 IOC，也不能据此判定主机安全，因为后续阶段和清理行为仍不完全明确",
		}
	}

	if len(report.Processes) > 0 {
		hostAssessment.Reasons = append(hostAssessment.Reasons, fmt.Sprintf("当前仍有 %d 个 Apifox 进程在运行", len(report.Processes)))
	}
	hostAssessment = buildAssessment(hostAssessment.Severity, hostAssessment.Label, hostAssessment.Reasons)

	return hostAssessment
}

func defaultRecommendations(report *Report) []string {
	var steps []string
	switch report.Assessment.CompromiseStatus {
	case "evidence-of-compromise":
		steps = []string{
			"把该主机按已中招主机处理：先隔离，再继续留证和处置。",
			"立即停止继续使用 Apifox，并优先轮换 SSH、Git、Kubernetes、npm 等高价值凭证。",
			"清理前先保全 Apifox 用户数据目录；如需本地复制命中 IOC 的文件，可使用 -copy-apifox-evidence。",
		}
	case "review-required":
		steps = []string{
			"先按 JSON 报告中每条命中的 review.standard 和 review.steps 做人工复审，再决定是否升级为中招主机。",
			"在复审结论出来前，避免继续在该主机上使用 Apifox 处理敏感凭证。",
			"如果复审后仍无法排除异常，再把该主机按已中招主机处理。",
		}
	case "exposure-risk":
		steps = []string{
			"当前更像暴露风险而不是已确认中招，优先核对攻击窗口内是否实际使用过受影响版本 Apifox。",
			"若该用户目录存在高价值凭证，先做凭证轮换，再继续看是否还有启动项或命令历史异常。",
			"如 Apifox 安装在非标准路径，请使用 -extra-root 指向真实目录后重扫。",
		}
	default:
		steps = []string{
			"本轮扫描在当前范围内未发现明确中招迹象。",
			"如 Apifox 安装在非标准路径或便携目录，请使用 -extra-root 补扫真实位置。",
			"当前结果只代表这次分诊范围，不等于绝对干净。",
		}
	}
	if extraRootMode(report.ExtraRootMode) == "external" && countExtraRootHits(report.ExtraRootFindings) > 0 {
		steps = append([]string{"额外扫描目录中发现了 IOC。若这些目录属于其他主机或挂载证据，请将对应主机单独按已中招处理；若这些目录其实属于本机便携版 Apifox，请使用 -extra-root-mode local 重扫。"}, steps...)
	}
	if len(report.WindowsArtifacts.RegistryAutoruns) > 0 || len(report.WindowsArtifacts.PrefetchHits) > 0 {
		steps = append([]string{"Windows 主机请优先复核报告中命中的 Run/RunOnce 注册表项和 Prefetch，再判断是否已经脱离 Apifox 进程。"}, steps...)
	}
	if (len(report.SystemPersistenceFindings) > 0 || hasAnyProfilePersistence(report.Profiles)) && report.Assessment.CompromiseStatus != "no-clear-compromise-evidence" {
		steps = append([]string{"如果报告中出现 Startup、LaunchAgent、计划任务或 systemd 命中，先确认这些条目是否属于正常软件更新、IT 管理脚本或已知企业基线。"}, steps...)
	}
	return dedupeStrings(steps)
}

func buildAssessment(severity, label string, reasons []string) Assessment {
	status := compromiseStatusFromLabel(label)
	return Assessment{
		Severity:             severity,
		SeverityText:         severityCN(severity),
		Label:                label,
		LabelText:            assessmentLabelCN(label),
		CompromiseStatus:     status,
		CompromiseStatusText: compromiseStatusCN(status),
		Reasons:              reasons,
	}
}

func profileNotes(profile ProfileReport, cfg Config) []string {
	var notes []string
	if len(profile.ApifoxHits) == 0 {
		notes = append(notes, "在已扫描的 Apifox 文件中未发现残留事件 IOC 字符串。")
	}
	if len(profile.CommandHistoryHits) == 0 {
		notes = append(notes, "命令历史中未命中当前实现的 IOC 或高风险执行链规则。")
	}
	if len(profile.PersistenceFindings) == 0 {
		notes = append(notes, "在本工具扫描的用户启动位置中未发现可疑持久化证据。")
	}
	if hasExistingApifoxDir(profile.ApifoxDirs) && !profile.ActivityDuringIncident {
		notes = append(notes, fmt.Sprintf("存在 Apifox 目录，但其最新文件时间戳不在 %s 到 %s 的攻击窗口内。", cfg.IncidentStart.Format(time.DateOnly), cfg.IncidentEnd.Format(time.DateOnly)))
	}
	if !hasExistingApifoxDir(profile.ApifoxDirs) {
		notes = append(notes, "如果 Apifox 以便携版或非标准路径安装，请使用 -extra-root 指向对应目录后重新扫描。")
	}
	return notes
}

func countExtraRootHits(findings []ExtraRootFinding) int {
	total := 0
	for _, finding := range findings {
		total += len(finding.Hits)
	}
	return total
}

func inIncidentWindow(ts, start, end time.Time) bool {
	return (ts.Equal(start) || ts.After(start)) && (ts.Equal(end) || ts.Before(end))
}

func sortHits(hits []FileHit) {
	sort.Slice(hits, func(i, j int) bool {
		if len(hits[i].MatchedTokens) == len(hits[j].MatchedTokens) {
			return hits[i].Path < hits[j].Path
		}
		return len(hits[i].MatchedTokens) > len(hits[j].MatchedTokens)
	})
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		cleaned := filepath.Clean(strings.TrimSpace(value))
		if cleaned == "" || seen[cleaned] {
			continue
		}
		seen[cleaned] = true
		out = append(out, cleaned)
	}
	sort.Strings(out)
	return out
}

func countPersistenceIOCFindings(findings []PersistenceFinding) int {
	count := 0
	for _, finding := range findings {
		if len(finding.MatchedTokens) > 0 {
			count++
		}
	}
	return count
}

func hasAnyProfilePersistence(profiles []ProfileReport) bool {
	for _, profile := range profiles {
		if len(profile.PersistenceFindings) > 0 {
			return true
		}
	}
	return false
}

func countManualReviewItems(report *Report) int {
	count := 0
	for _, profile := range report.Profiles {
		for _, hit := range profile.ApifoxHits {
			if hit.Review.Required {
				count++
			}
		}
		for _, hit := range profile.CommandHistoryHits {
			if hit.Review.Required {
				count++
			}
		}
		for _, finding := range profile.PersistenceFindings {
			if finding.Review.Required {
				count++
			}
		}
	}
	for _, finding := range report.SystemPersistenceFindings {
		if finding.Review.Required {
			count++
		}
	}
	for _, finding := range report.WindowsArtifacts.RegistryAutoruns {
		if finding.Review.Required {
			count++
		}
	}
	for _, hit := range report.WindowsArtifacts.PrefetchHits {
		if hit.Review.Required {
			count++
		}
	}
	for _, finding := range report.ExtraRootFindings {
		for _, hit := range finding.Hits {
			if hit.Review.Required {
				count++
			}
		}
	}
	return count
}

func countRegistryIOCFindings(findings []RegistryAutorun) int {
	count := 0
	for _, finding := range findings {
		if len(finding.MatchedTokens) > 0 || containsReasonFragment(finding.Reasons, "引用 apifox") || containsReasonFragment(finding.Reasons, "references apifox") {
			count++
		}
	}
	return count
}

func containsReasonFragment(reasons []string, fragment string) bool {
	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), strings.ToLower(fragment)) {
			return true
		}
	}
	return false
}
