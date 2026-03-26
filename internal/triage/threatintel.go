package triage

func defaultThreatIntel() ThreatIntel {
	return ThreatIntel{
		ConfirmedBehaviors: []string{
			"2026-03-25 公布的完整逆向分析显示：投毒 CDN 文件（77KB）在正常 SDK（34KB）后追加了 42KB 严重混淆恶意代码（7 层混淆 + 反调试），活跃期为 2026-03-04 至 2026-03-22（18 天）。",
			"Stage-1 恶意代码采集机器指纹（MAC+CPU+hostname → SHA-256 = af_uuid），读取 Apifox localStorage 中的 common.accessToken，调用官方 API 获取用户邮箱/姓名，经 RSA-2048 OAEP 加密后附加到所有 C2 请求头（af_uuid/af_os/af_user/af_name/af_apifox_user/af_apifox_name）。",
			"Stage-2 v1（collectPreInformations）已确认窃取：~/.ssh/*（全部密钥）、~/.zsh_history、~/.bash_history、~/.git-credentials、ps aux（macOS/Linux）/ tasklist（Windows），经 JSON → Gzip → AES-256-GCM（密钥:apifox/盐值:foxapi/scryptSync派生）加密后 POST 到 /event/0/log。",
			"Stage-2 v2（collectAddInformations）已确认新增窃取：~/.kube/*、~/.zshrc、~/.npmrc、~/.subversion/*、主目录/桌面/文档目录树（深度1-2层），Windows 额外扫描 D:/E:/F: 盘符，POST 到 /event/2/log。",
			"C2（apifox.it.com）通过 Cloudflare CDN 托管，Stage-2 URL 为一次性随机 8 位 hex 路径（历史路径返回 404），用完即焚、DOM 自清理，服务端将 af_uuid 硬编码到每次下发的 Stage-2 中实现受害者追踪。",
			"攻击者将 RSA-2048 私钥嵌入客户端恶意 JS（PKCS#8，特征前缀 MIIEvQIBADANBgk），用于解密 C2 指令——这一失误使安全研究人员能完整还原所有已捕获载荷。",
			"Stage-2 源码中保留完整中文注释（如'盐值也必须提供'），与入口层 7 层混淆形成强烈反差，暗示入口混淆和后端载荷可能非同一人编写。",
		},
		CapabilityNotes: []string{
			"核心架构：eval(rsaDecrypt(c2_response))——C2 服务器可在每次 Apifox 运行周期内（30 分钟到 3 小时随机轮询）下发完全不同的任意 JavaScript，是完整的灵活远程代码执行平台，不能只按'凭证窃取'处理。",
			"攻击者可根据已回传的 SSH 密钥目标（可达服务器）、K8s 配置（集群规模/OIDC token）、npm Token、Git Token、Apifox 邮箱（判断所属公司）等数据筛选高价值目标，下发定制化后续载荷（横向移动/后门植入/二次供应链投毒）。",
			"数据外泄全程加密（RSA 头部 + AES-256-GCM 正文 + Gzip 压缩），可绕过基于内容明文的 DLP 检测；随机轮询间隔避免产生规律性网络流量；.it.com 非标准域名规避 WHOIS 追踪。",
		},
		Inferences: []string{
			"结合公开样本和 Electron 安全模型推断：如果 C2 在某次轮询中投放了 LaunchAgent、启动项、计划任务或独立服务，那么即使 Apifox 被关闭或卸载，后续主机活动仍可能持续存在。",
			"即便 Apifox 数据目录扫描结果干净，也不能排除纯内存执行、DOM 自清理后的后续载荷，或 C2 已针对该主机执行了超出凭证窃取范围的深度操作。",
			"攻击活跃窗口 18 天内，C2 至少下发了 10 次不同 Stage-2 URL（已观测到 2026-03-12 至 2026-03-20 的样本），受害者在此期间每次启动 Apifox 均可能接受不同指令。",
			"C2 DNS 于 2026-03-22 下线，但 2026-03-25 验证时源站 IP 仍在响应——在 C2 未完全关闭前，已受感染主机上仍运行的 Apifox 进程理论上可继续接受后续指令。",
		},
		Sources: []SourceReference{
			{
				Title:         "Apifox 供应链投毒攻击 - 完整技术分析",
				URL:           "https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/",
				PublishedDate: "2026-03-25",
				Notes:         "2026 年 3 月事件行为和 IOC 集合的主要公开逆向来源，包含 RSA 私钥提取、Stage-2 载荷解密和完整攻击链还原。",
			},
			{
				Title:         "部分反混淆 JS（phith0n gist）",
				URL:           "hxxps://gist.github.com/phith0n/7020c55bf241b2f3ccf5254192bd48a5",
				PublishedDate: "2026-03",
				Notes:         "部分反混淆后的恶意 JS 源码，可用于比对本地缓存文件。",
			},
			{
				Title:         "Wayback Machine 存档（投毒版本 77KB）",
				URL:           "hxxps://web.archive.org/web/20260305160602/https://cdn.apifox.com/www/assets/js/user-tracking.min.js",
				PublishedDate: "2026-03-05",
				Notes:         "被 Wayback Machine 于 2026-03-05 抓取存档的投毒 JS 文件，可用于哈希比对。",
			},
			{
				Title:         "Electron 安全教程",
				URL:           "https://www.electronjs.org/docs/latest/tutorial/security",
				PublishedDate: "current",
				Notes:         "Electron 官方文档，明确警告在启用 Node integration 的渲染进程中执行远程代码存在高风险。",
			},
		},
	}
}
