package triage

func assessmentLabelCN(label string) string {
	switch label {
	case "host-ioc-found":
		return "发现主机 IOC"
	case "likely-exposed-host":
		return "疑似暴露主机"
	case "possible-post-exploitation":
		return "疑似二阶段利用"
	case "manual-review-required":
		return "需要人工复审"
	case "apifox-active-during-window":
		return "攻击窗口内存在使用痕迹"
	case "no-apifox-artifacts-found":
		return "未发现 Apifox 痕迹"
	case "credentials-at-risk":
		return "凭证存在风险"
	case "no-clear-host-ioc":
		return "未发现明确 IOC"
	default:
		return label
	}
}

func compromiseStatusFromLabel(label string) string {
	switch label {
	case "host-ioc-found", "possible-post-exploitation":
		return "evidence-of-compromise"
	case "manual-review-required":
		return "review-required"
	case "likely-exposed-host", "apifox-active-during-window", "credentials-at-risk":
		return "exposure-risk"
	case "no-apifox-artifacts-found", "no-clear-host-ioc":
		return "no-clear-compromise-evidence"
	default:
		return label
	}
}

func compromiseStatusCN(status string) string {
	switch status {
	case "evidence-of-compromise":
		return "已发现中招迹象"
	case "review-required":
		return "存在可疑迹象，需人工复审"
	case "exposure-risk":
		return "存在暴露风险，建议跟进"
	case "no-clear-compromise-evidence":
		return "当前未发现明确中招迹象"
	default:
		return status
	}
}

func severityCN(severity string) string {
	switch severity {
	case "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	default:
		return severity
	}
}

func reviewStandardCN(standard string) string {
	switch standard {
	case "direct_ioc":
		return "直接 IOC"
	case "behavioral_correlation":
		return "行为关联"
	case "execution_artifact":
		return "执行痕迹"
	default:
		return standard
	}
}
