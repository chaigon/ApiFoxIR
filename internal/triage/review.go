package triage

func defaultReviewStandards() []ReviewStandard {
	return []ReviewStandard{
		{
			Name:        "direct_ioc",
			Confidence:  "高",
			Description: "该证据直接包含公开 IOC，或直接引用了与恶意加载链相关的 Apifox 内容。",
			ReviewSteps: []string{
				"打开原始证据，确认 IOC 是真实内容而不是分析资料、复盘笔记或复制粘贴的文本。",
				"对证据计算哈希，并与现有 EDR、杀软告警或案件记录做比对。",
				"围绕其中提到的路径、域名或命令，继续关联进程创建日志、父子进程关系和网络日志。",
			},
		},
		{
			Name:        "behavioral_correlation",
			Confidence:  "中",
			Description: "该证据命中了多种可疑行为组合，例如启动项执行、解释器调用、网络下载器或用户可写路径，并且时间落在已知攻击窗口附近。",
			ReviewSteps: []string{
				"检查完整命令或文件内容，判断它是否属于已知的 IT 自动化、软件安装器或开发脚本。",
				"核对文件签名、发布者、哈希信誉和安装路径归属。",
				"把证据时间与软件安装、运维工单、Helpdesk 操作和 EDR 遥测关联后，再决定是否升级为恶意。",
			},
		},
		{
			Name:        "execution_artifact",
			Confidence:  "中",
			Description: "该证据只能说明某个二进制或脚本解释器在攻击窗口内被执行过，本身不足以直接证明恶意。",
			ReviewSteps: []string{
				"继续查看相邻执行证据，例如 Prefetch 邻近项、Jump List、命令历史和进程创建日志。",
				"判断该执行更像是正常运维、开发流程，还是可疑的后续利用行为。",
				"把它作为时间线 pivot 使用，而不是单独拿来下受害结论。",
			},
		},
	}
}

func reviewGuidance(standard, why string) ReviewGuidance {
	for _, item := range defaultReviewStandards() {
		if item.Name == standard {
			return ReviewGuidance{
				Required:     true,
				Standard:     item.Name,
				StandardText: reviewStandardCN(item.Name),
				Confidence:   item.Confidence,
				Why:          why,
				Steps:        item.ReviewSteps,
			}
		}
	}
	return ReviewGuidance{
		Required:     true,
		Standard:     standard,
		StandardText: reviewStandardCN(standard),
		Confidence:   "中",
		Why:          why,
	}
}
