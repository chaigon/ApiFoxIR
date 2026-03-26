package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"ApiFoxIR/internal/triage"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	var (
		all               bool
		dryRun            bool
		removeApifoxDirs  bool
		removePersistence bool
		maxFileSizeMB     int
		extraRoots        multiFlag
	)

	flag.BoolVar(&all, "all", false,
		"全量清理模式：同时开启 -remove-apifox-dirs 和 -remove-persistence，清除所有 Apifox 数据及持久化条目。")
	flag.BoolVar(&dryRun, "dry-run", true,
		"预演模式：只打印将被删除的路径，不实际删除（默认开启，需要显式 -dry-run=false 才真正删除）。")
	flag.BoolVar(&removeApifoxDirs, "remove-apifox-dirs", false,
		"整体删除 Apifox Electron 用户数据目录（含 LevelDB、缓存、Network 等）。\n"+
			"不指定时只删除 LevelDB 中含 IOC 的 .ldb/.log 文件。")
	flag.BoolVar(&removePersistence, "remove-persistence", false,
		"删除持久化位置（LaunchAgent/Startup/systemd）中文件名包含 apifox 或内容命中 IOC 的条目。")
	flag.IntVar(&maxFileSizeMB, "max-file-size-mb", 32,
		"扫描文件内容时跳过大于该大小（MiB）的文件。")
	flag.Var(&extraRoots, "extra-root",
		"额外需要清理的 Apifox 数据目录（可重复指定，对应取证时的 -extra-root）。")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `ApiFoxIR-clean — Apifox 供应链事件清理工具

用法：
  ApiFoxIR-clean [选项]

清理范围（默认仅删除 LevelDB 中含 IOC 的文件）：
  1. Apifox LevelDB 中的恶意 localStorage 键（_rl_headers/_rl_mc）
  2. （可选）整个 Apifox 用户数据目录（-remove-apifox-dirs）
  3. （可选）持久化位置中命中 IOC 或引用 apifox 的条目（-remove-persistence）

常用示例：
  ApiFoxIR-clean -all                        # 预演：查看全量清理将删除的所有内容
  ApiFoxIR-clean -all -dry-run=false         # 实际执行全量清理（需按 Enter 确认）
  ApiFoxIR-clean -dry-run=false              # 仅清理 LevelDB IOC 文件（最保守模式）

安全提示：
  - 默认 -dry-run=true，不会实际删除任何内容。
  - 真正执行前请先用默认模式确认输出内容，再加 -dry-run=false 重跑。
  - 建议删除前先用 ApiFoxIR 生成取证报告留存证据。

选项：
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	// -all 覆盖各细分开关
	if all {
		removeApifoxDirs = true
		removePersistence = true
	}

	cfg := triage.CleanupConfig{
		DryRun:            dryRun,
		RemoveApifoxDirs:  removeApifoxDirs,
		RemovePersistence: removePersistence,
		MaxFileSize:       int64(maxFileSizeMB) << 20,
		ExtraRoots:        extraRoots,
	}

	if !dryRun {
		fmt.Fprintln(os.Stderr, "⚠️  警告：-dry-run=false 已设置，本次将实际删除文件！")
		fmt.Fprintln(os.Stderr, "   按 Enter 继续，或 Ctrl-C 中止……")
		var dummy string
		fmt.Fscanln(os.Stdin, &dummy)
	}

	report, err := triage.RunCleanup(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "清理失败：%v\n", err)
		os.Exit(1)
	}

	fmt.Println(triage.RenderCleanupSummary(report))

	// 打印可能存在的 Apifox 安装路径供参考
	installPaths := triage.ApifoxInstallPaths()
	if len(installPaths) > 0 {
		fmt.Println()
		fmt.Println("发现以下 Apifox 安装目录（本工具不自动删除，请手动卸载）：")
		for _, p := range installPaths {
			fmt.Printf("  %s\n", p)
		}
	}

	if len(report.Errors) > 0 {
		os.Exit(1)
	}
}
