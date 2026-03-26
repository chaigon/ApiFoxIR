package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ApiFoxIR/internal/triage"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	var (
		outputDir          string
		outputFormat       string
		extraRootMode      string
		maxFileSizeMB      int
		copyApifoxEvidence bool
		incidentStartRaw   string
		incidentEndRaw     string
		extraRoots         multiFlag
	)

	flag.StringVar(&outputDir, "out", "out", "输出目录，用于保存 JSON 报告和可选的留证文件。")
	flag.StringVar(&outputFormat, "format", "markdown", "终端摘要和摘要文件输出格式，可选 markdown、text。默认 markdown。")
	flag.StringVar(&extraRootMode, "extra-root-mode", "external", "额外扫描目录的作用域，可选 external、local。默认 external，避免把挂载证据目录误算成本机中招。")
	flag.IntVar(&maxFileSizeMB, "max-file-size-mb", 32, "跳过大于该大小（MiB）的文件。")
	flag.BoolVar(&copyApifoxEvidence, "copy-apifox-evidence", false, "将命中 IOC 的 Apifox/Electron 文件复制到输出目录。")
	flag.StringVar(&incidentStartRaw, "incident-start", triage.DefaultIncidentStart.Format(time.DateOnly), "攻击窗口开始日期（YYYY-MM-DD）。")
	flag.StringVar(&incidentEndRaw, "incident-end", triage.DefaultIncidentEnd.Format(time.DateOnly), "攻击窗口结束日期（YYYY-MM-DD）。")
	flag.Var(&extraRoots, "extra-root", "额外扫描目录，可重复指定。")
	flag.Parse()

	start, err := time.Parse(time.DateOnly, incidentStartRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-incident-start 参数无效：%v\n", err)
		os.Exit(2)
	}

	endDate, err := time.Parse(time.DateOnly, incidentEndRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-incident-end 参数无效：%v\n", err)
		os.Exit(2)
	}
	normalizedFormat, err := triage.NormalizeOutputFormat(outputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-format 参数无效：%v\n", err)
		os.Exit(2)
	}
	normalizedExtraRootMode, err := triage.NormalizeExtraRootMode(extraRootMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-extra-root-mode 参数无效：%v\n", err)
		os.Exit(2)
	}

	cfg := triage.Config{
		OutputDir:          outputDir,
		MaxFileSize:        int64(maxFileSizeMB) << 20,
		CopyApifoxEvidence: copyApifoxEvidence,
		IncidentStart:      start,
		IncidentEnd:        endDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second),
		ExtraRoots:         extraRoots,
		ExtraRootMode:      normalizedExtraRootMode,
	}

	report, err := triage.Run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "扫描失败：%v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "创建输出目录失败：%v\n", err)
		os.Exit(1)
	}

	jsonPath := filepath.Join(outputDir, "report.json")
	if err := triage.WriteJSON(report, jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "写入 JSON 报告失败：%v\n", err)
		os.Exit(1)
	}

	summary, err := triage.RenderSummary(report, normalizedFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "渲染摘要失败：%v\n", err)
		os.Exit(1)
	}
	summaryPath := filepath.Join(outputDir, triage.SummaryFileName(normalizedFormat))
	if err := os.WriteFile(summaryPath, []byte(summary+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入摘要文件失败：%v\n", err)
		os.Exit(1)
	}

	fmt.Println(summary)
	fmt.Printf("\n摘要文件：%s\n", summaryPath)
	fmt.Printf("JSON 报告：%s\n", jsonPath)
	if report.EvidenceDir != "" {
		fmt.Printf("留证文件：%s\n", report.EvidenceDir)
	}
}
