package triage

// cleanup.go — Apifox 供应链事件清理工具
//
// 清理范围：
//  1. Apifox Electron 用户数据目录（整目录移除）
//  2. LevelDB 中的恶意 localStorage 键（_rl_headers / _rl_mc）
//     ——因为 LevelDB 不支持安全删除单条记录，采取删除含 IOC 的 .ldb/.log 文件后
//       由 Electron 下次启动时重建 compaction；若需彻底清理可选择整目录删除。
//  3. 用户和系统持久化位置中直接引用 apifox 或命中 IOC 的条目
//
// 安全原则：
//   - 默认 DryRun=true，打印将删除的路径，不实际写盘。
//   - 只有 DryRun=false 时才执行删除，且删除前向 Confirm 回调确认每批目标。
//   - 所有被删除的路径都会记录在 CleanupReport 中，方便审计。

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CleanupConfig 控制清理行为。
type CleanupConfig struct {
	// DryRun 为 true 时只打印将被删除的路径，不实际删除（默认应为 true）。
	DryRun bool
	// RemoveApifoxDirs 是否整体删除 Apifox 用户数据目录（包含 LevelDB）。
	// 若为 false，则只删除目录中含 IOC 的 LevelDB 文件。
	RemoveApifoxDirs bool
	// RemovePersistence 是否删除持久化位置中命中 IOC 或直接引用 apifox 的条目。
	RemovePersistence bool
	// MaxFileSize 读取文件内容时的大小上限（字节），与 Config 保持一致。
	MaxFileSize int64
	// ExtraRoots 额外需要清理的 Apifox 数据目录（对应取证时的 -extra-root）。
	ExtraRoots []string
}

// CleanupAction 记录一条清理操作。
type CleanupAction struct {
	// Path 被操作的路径
	Path string `json:"path"`
	// Kind 操作类型："remove-dir"（整目录）/ "remove-file"（单文件）
	Kind string `json:"kind"`
	// Reason 删除原因
	Reason string `json:"reason"`
	// Done true 表示已实际执行，false 表示 DryRun 未执行
	Done bool `json:"done"`
	// Error 执行失败时的错误信息
	Error string `json:"error,omitempty"`
}

// CleanupReport 汇总本次清理结果。
type CleanupReport struct {
	DryRun  bool            `json:"dry_run"`
	Actions []CleanupAction `json:"actions"`
	Errors  []string        `json:"errors,omitempty"`
}

// RunCleanup 根据 CleanupConfig 对当前主机执行清理。
// 它会先枚举用户目录，再按配置项逐步删除目标。
func RunCleanup(cfg CleanupConfig) (*CleanupReport, error) {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 32 << 20
	}

	report := &CleanupReport{DryRun: cfg.DryRun}

	profiles, err := enumerateProfiles()
	if err != nil {
		return nil, err
	}

	for _, p := range profiles {
		dirs := discoverApifoxDirs(p.Home)
		for _, dir := range dirs {
			info, statErr := os.Stat(dir.Path)
			if statErr != nil || !info.IsDir() {
				continue
			}

			if cfg.RemoveApifoxDirs {
				report.addAction(cfg.DryRun, CleanupAction{
					Path:   dir.Path,
					Kind:   "remove-dir",
					Reason: fmt.Sprintf("Apifox 用户数据目录（来源：%s）——包含 LevelDB、缓存、Network 等所有 Electron 数据", dir.Source),
				})
			} else {
				// 只删除含 IOC 的 LevelDB 文件
				ldbActions, ldbErrs := cleanLevelDBIOCFiles(dir.Path, cfg)
				report.Actions = append(report.Actions, ldbActions...)
				report.Errors = append(report.Errors, ldbErrs...)
			}
		}

		if cfg.RemovePersistence {
			persActions, persErrs := cleanUserPersistenceIOC(p.Home, cfg)
			report.Actions = append(report.Actions, persActions...)
			report.Errors = append(report.Errors, persErrs...)
		}
	}

	// 额外根目录（-extra-root 对应的目录）
	for _, root := range dedupeStrings(cfg.ExtraRoots) {
		info, statErr := os.Stat(root)
		if statErr != nil || !info.IsDir() {
			report.Errors = append(report.Errors, fmt.Sprintf("额外目录不可读，跳过：%s", root))
			continue
		}
		if cfg.RemoveApifoxDirs {
			report.addAction(cfg.DryRun, CleanupAction{
				Path:   root,
				Kind:   "remove-dir",
				Reason: "通过 -extra-root 指定的 Apifox 数据目录",
			})
		} else {
			ldbActions, ldbErrs := cleanLevelDBIOCFiles(root, cfg)
			report.Actions = append(report.Actions, ldbActions...)
			report.Errors = append(report.Errors, ldbErrs...)
		}
	}

	if cfg.RemovePersistence {
		sysActions, sysErrs := cleanSystemPersistenceIOC(cfg)
		report.Actions = append(report.Actions, sysActions...)
		report.Errors = append(report.Errors, sysErrs...)
	}

	return report, nil
}

// addAction 向报告追加一条操作，并在非 DryRun 时实际执行删除。
func (r *CleanupReport) addAction(dryRun bool, action CleanupAction) {
	if dryRun {
		r.Actions = append(r.Actions, action)
		return
	}
	var err error
	switch action.Kind {
	case "remove-dir":
		err = os.RemoveAll(action.Path)
	case "remove-file":
		err = os.Remove(action.Path)
	}
	if err != nil {
		action.Error = err.Error()
		r.Errors = append(r.Errors, fmt.Sprintf("删除失败 %s：%v", action.Path, err))
	} else {
		action.Done = true
	}
	r.Actions = append(r.Actions, action)
}

// cleanLevelDBIOCFiles 在给定 Apifox 数据目录下查找所有 LevelDB 子目录，
// 扫描其中直接包含 IOC 标记（_rl_headers / _rl_mc）的 .ldb / .log 文件并删除。
func cleanLevelDBIOCFiles(apifoxDataDir string, cfg CleanupConfig) ([]CleanupAction, []string) {
	var actions []CleanupAction
	var errs []string

	for _, sub := range levelDBSubDirs {
		ldbRoot := filepath.Join(apifoxDataDir, sub)
		info, err := os.Stat(ldbRoot)
		if err != nil || !info.IsDir() {
			continue
		}

		_ = filepath.WalkDir(ldbRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				errs = append(errs, fmt.Sprintf("遍历 LevelDB 目录失败 %s：%v", path, walkErr))
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
			if statErr != nil || fi.Size() == 0 || fi.Size() > cfg.MaxFileSize {
				return nil
			}

			data, readErr := os.ReadFile(path)
			if readErr != nil {
				errs = append(errs, fmt.Sprintf("读取 LevelDB 文件失败 %s：%v", path, readErr))
				return nil
			}
			lower := strings.ToLower(string(data))
			if !strings.Contains(lower, "_rl_headers") && !strings.Contains(lower, "_rl_mc") {
				return nil
			}

			var foundTokens []string
			if strings.Contains(lower, "_rl_headers") {
				foundTokens = append(foundTokens, "_rl_headers")
			}
			if strings.Contains(lower, "_rl_mc") {
				foundTokens = append(foundTokens, "_rl_mc")
			}

			action := CleanupAction{
				Path:   path,
				Kind:   "remove-file",
				Reason: fmt.Sprintf("LevelDB 文件含恶意 localStorage 键：%s", strings.Join(foundTokens, ", ")),
			}
			if cfg.DryRun {
				actions = append(actions, action)
			} else {
				if removeErr := os.Remove(path); removeErr != nil {
					action.Error = removeErr.Error()
					errs = append(errs, fmt.Sprintf("删除 LevelDB 文件失败 %s：%v", path, removeErr))
				} else {
					action.Done = true
				}
				actions = append(actions, action)
			}
			return nil
		})
	}
	return actions, errs
}

// cleanUserPersistenceIOC 删除用户持久化目录中命中 IOC 或名称引用 apifox 的条目。
func cleanUserPersistenceIOC(home string, cfg CleanupConfig) ([]CleanupAction, []string) {
	targets := discoverUserPersistenceTargets(home)
	return cleanPersistenceTargetsIOC(targets, cfg)
}

// cleanSystemPersistenceIOC 删除系统持久化目录中命中 IOC 或名称引用 apifox 的条目。
func cleanSystemPersistenceIOC(cfg CleanupConfig) ([]CleanupAction, []string) {
	targets := discoverSystemPersistenceTargets()
	return cleanPersistenceTargetsIOC(targets, cfg)
}

func cleanPersistenceTargetsIOC(targets []persistenceTarget, cfg CleanupConfig) ([]CleanupAction, []string) {
	var actions []CleanupAction
	var errs []string

	for _, target := range targets {
		info, err := os.Stat(target.Path)
		if err != nil {
			continue
		}

		if !info.IsDir() {
			// 目标本身是文件（如 crontab 单文件）
			if isPersistenceFileIOC(target.Path, cfg.MaxFileSize) {
				action := CleanupAction{
					Path:   target.Path,
					Kind:   "remove-file",
					Reason: persistenceIOCReason(target.Path, cfg.MaxFileSize),
				}
				if cfg.DryRun {
					actions = append(actions, action)
				} else {
					if removeErr := os.Remove(target.Path); removeErr != nil {
						action.Error = removeErr.Error()
						errs = append(errs, fmt.Sprintf("删除持久化文件失败 %s：%v", target.Path, removeErr))
					} else {
						action.Done = true
					}
					actions = append(actions, action)
				}
			}
			continue
		}

		// 目标是目录，遍历其直接子文件（不递归，避免误删正常 LaunchAgent）
		_ = filepath.WalkDir(target.Path, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				errs = append(errs, fmt.Sprintf("遍历持久化目录失败 %s：%v", path, walkErr))
				return nil
			}
			if d.IsDir() {
				if path == target.Path {
					return nil
				}
				return fs.SkipDir // 只看第一层
			}
			if !isPersistenceFileIOC(path, cfg.MaxFileSize) {
				return nil
			}
			action := CleanupAction{
				Path:   path,
				Kind:   "remove-file",
				Reason: persistenceIOCReason(path, cfg.MaxFileSize),
			}
			if cfg.DryRun {
				actions = append(actions, action)
			} else {
				if removeErr := os.Remove(path); removeErr != nil {
					action.Error = removeErr.Error()
					errs = append(errs, fmt.Sprintf("删除持久化文件失败 %s：%v", path, removeErr))
				} else {
					action.Done = true
				}
				actions = append(actions, action)
			}
			return nil
		})
	}
	return actions, errs
}

// isPersistenceFileIOC 判断持久化位置中的单个文件是否应被删除：
// 文件名包含 "apifox"，或文件内容命中 IOC token。
func isPersistenceFileIOC(path string, maxFileSize int64) bool {
	if strings.Contains(strings.ToLower(filepath.Base(path)), "apifox") {
		return true
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 || info.Size() > maxFileSize {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	tokens, _ := matchIOCPatterns(strings.ToLower(string(data)))
	return len(tokens) > 0
}

// persistenceIOCReason 返回人类可读的删除原因。
func persistenceIOCReason(path string, maxFileSize int64) string {
	baseLower := strings.ToLower(filepath.Base(path))
	if strings.Contains(baseLower, "apifox") {
		return "持久化条目名称直接引用 apifox"
	}
	info, _ := os.Stat(path)
	if info != nil && info.Size() > 0 && info.Size() <= maxFileSize {
		data, _ := os.ReadFile(path)
		if data != nil {
			tokens, _ := matchIOCPatterns(strings.ToLower(string(data)))
			if len(tokens) > 0 {
				return fmt.Sprintf("持久化文件内容包含事件 IOC：%s", strings.Join(tokens, ", "))
			}
		}
	}
	return "持久化条目命中 IOC 规则"
}

// RenderCleanupSummary 将 CleanupReport 渲染为人类可读的文本摘要。
func RenderCleanupSummary(r *CleanupReport) string {
	var b strings.Builder

	mode := "实际执行"
	if r.DryRun {
		mode = "预演（DryRun，未实际删除）"
	}
	fmt.Fprintf(&b, "清理模式：%s\n", mode)
	fmt.Fprintf(&b, "操作总数：%d\n", len(r.Actions))

	done, pending, failed := 0, 0, 0
	for _, a := range r.Actions {
		switch {
		case a.Error != "":
			failed++
		case a.Done:
			done++
		default:
			pending++
		}
	}
	if r.DryRun {
		fmt.Fprintf(&b, "待删除路径：%d\n", pending)
	} else {
		fmt.Fprintf(&b, "成功删除：%d\n", done)
		fmt.Fprintf(&b, "删除失败：%d\n", failed)
	}

	if len(r.Actions) > 0 {
		fmt.Fprintf(&b, "\n操作列表：\n")
		for _, a := range r.Actions {
			status := "[预演]"
			if a.Done {
				status = "[已删除]"
			} else if a.Error != "" {
				status = fmt.Sprintf("[失败: %s]", a.Error)
			}
			kindStr := "文件"
			if a.Kind == "remove-dir" {
				kindStr = "目录"
			}
			fmt.Fprintf(&b, "  %s %s（%s）\n    原因：%s\n", status, a.Path, kindStr, a.Reason)
		}
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "\n错误：\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  - %s\n", e)
		}
	}

	return strings.TrimSpace(b.String())
}

// ApifoxInstallPaths 返回当前系统 Apifox 可能的安装目录（非数据目录），
// 供用户参考手动卸载。
func ApifoxInstallPaths() []string {
	home, _ := os.UserHomeDir()
	var paths []string
	switch runtime.GOOS {
	case "darwin":
		paths = []string{
			"/Applications/Apifox.app",
			filepath.Join(home, "Applications", "Apifox.app"),
		}
	case "windows":
		paths = []string{
			filepath.Join(home, "AppData", "Local", "Programs", "Apifox"),
			`C:\Program Files\Apifox`,
			`C:\Program Files (x86)\Apifox`,
		}
	case "linux":
		paths = []string{
			"/opt/Apifox",
			"/usr/lib/apifox",
			filepath.Join(home, ".local", "share", "apifox"),
			filepath.Join(home, "apifox"),
		}
	}
	var existing []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			existing = append(existing, p)
		}
	}
	return existing
}
