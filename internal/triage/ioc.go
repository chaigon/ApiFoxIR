package triage

import "time"

type IOCPattern struct {
	Token     string `json:"token"`
	Category  string `json:"category"`
	Rationale string `json:"rationale"`
}

type SensitiveSpec struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"`
	RelativePaths []string `json:"relative_paths"`
}

var (
	DefaultIncidentStart = time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)
	DefaultIncidentEnd   = time.Date(2026, 3, 22, 23, 59, 59, 0, time.UTC)
)

var DefaultIOCPatterns = []IOCPattern{
	{
		Token:     "apifox.it.com",
		Category:  "network",
		Rationale: "2026 年 3 月 Apifox 供应链事件中已知的攻击者数据收集域名。",
	},
	{
		Token:     "/public/apifox-event.js",
		Category:  "payload",
		Rationale: "该事件中用于下发二阶段 JavaScript 的路径。",
	},
	{
		Token:     "/event/0/log",
		Category:  "network",
		Rationale: "一阶段脚本上报凭证信息时使用的接口路径。",
	},
	{
		Token:     "/event/2/log",
		Category:  "network",
		Rationale: "后续阶段上报文件清单或补充信息时使用的接口路径。",
	},
	{
		Token:     "_rl_headers",
		Category:  "local-storage",
		Rationale: "恶意代码注入到 Apifox localStorage 后用于缓存恶意请求头的键名。",
	},
	{
		Token:     "_rl_mc",
		Category:  "local-storage",
		Rationale: "恶意代码注入到 Apifox localStorage 后用于缓存加载器状态的键名。",
	},
	{
		Token:     "common.accesstoken",
		Category:  "local-storage",
		Rationale: "加载器会访问的 Apifox access token 存储位置，可用于确认应用暴露面。",
	},
	{
		Token:     "af_uuid",
		Category:  "header",
		Rationale: "被注入的恶意遥测代码添加的请求头。",
	},
	{
		Token:     "af_os",
		Category:  "header",
		Rationale: "被注入的恶意遥测代码添加的请求头。",
	},
	{
		Token:     "af_user",
		Category:  "header",
		Rationale: "被注入的恶意遥测代码添加的请求头。",
	},
	{
		Token:     "af_name",
		Category:  "header",
		Rationale: "被注入的恶意遥测代码添加的请求头。",
	},
	{
		Token:     "af_apifox_user",
		Category:  "header",
		Rationale: "可能出现在缓存 JavaScript 或本地存储中的恶意请求头字段。",
	},
	{
		Token:     "af_apifox_name",
		Category:  "header",
		Rationale: "可能出现在缓存 JavaScript 或本地存储中的恶意请求头字段。",
	},
	{
		Token:     "foxapi",
		Category:  "crypto",
		Rationale: "该事件中用于保护阶段载荷的特定口令/AES 盐值，在脚本或 LevelDB 中出现高度可疑。",
	},
	{
		Token:     "collectpreinformations",
		Category:  "payload",
		Rationale: "公开二阶段样本中的函数名，用于收集凭证路径和进程清单。",
	},
	{
		Token:     "collectaddinformations",
		Category:  "payload",
		Rationale: "公开二阶段样本中的函数名，用于进一步收集文件系统信息。",
	},
	{
		Token:     "miiEvqIBADANBgk",
		Category:  "crypto",
		Rationale: "攻击者嵌入恶意 JS 中的 RSA-2048 私钥 PKCS#8 Base64 特征前缀，出现即表示原始恶意脚本缓存存在。",
	},
	{
		Token:     "apifox-app-event-tracking",
		Category:  "payload",
		Rationale: "被投毒的 CDN JS 文件名特征，出现在非官方位置时表示投毒文件可能被缓存到本地。",
	},
	{
		Token:     "scryptsync",
		Category:  "crypto",
		Rationale: "Stage-2 载荷中用于 AES-256-GCM 密钥派生的函数调用特征，出现在本地文件中表示解密后的攻击载荷残留。",
	},
}

var DefaultSensitiveSpecs = []SensitiveSpec{
	{Name: "SSH 密钥", Kind: "directory", RelativePaths: []string{".ssh"}},
	{Name: "Kubernetes 配置", Kind: "directory", RelativePaths: []string{".kube"}},
	{Name: "Git 凭证", Kind: "file", RelativePaths: []string{".git-credentials"}},
	{Name: "npm 凭证", Kind: "file", RelativePaths: []string{".npmrc"}},
	{Name: "zsh 历史记录", Kind: "file", RelativePaths: []string{".zsh_history"}},
	{Name: "bash 历史记录", Kind: "file", RelativePaths: []string{".bash_history"}},
	{Name: "zsh 配置", Kind: "file", RelativePaths: []string{".zshrc"}},
	{Name: "Subversion 认证/配置", Kind: "directory", RelativePaths: []string{".subversion"}},
}

// LeakedCredentialType 描述一类已泄露或可能已泄露的凭证。
type LeakedCredentialType struct {
	// Kind 凭证类型标识，如 "ssh_private_key"、"git_token"
	Kind string `json:"kind"`
	// Label 中文可读名称
	Label string `json:"label"`
	// RiskLevel high / medium / low
	RiskLevel string `json:"risk_level"`
	// Evidence 支撑这条推断的证据描述
	Evidence string `json:"evidence"`
	// ActionRequired 必须执行的处置动作
	ActionRequired string `json:"action_required"`
}

// LeakageAnalysis 对本机可能已泄露数据的综合推断。
type LeakageAnalysis struct {
	// ExposedTypes 推断已暴露的凭证/数据类型列表
	ExposedTypes []LeakedCredentialType `json:"exposed_types,omitempty"`
	// RiskSummary 整体风险叙述
	RiskSummary string `json:"risk_summary"`
	// PostExploitationRisk 是否存在二阶段深度利用风险
	PostExploitationRisk bool `json:"post_exploitation_risk"`
	// PostExploitationNote 二阶段风险说明
	PostExploitationNote string `json:"post_exploitation_note,omitempty"`
}

// C2ContactEvidence 记录主机是否曾主动联系攻击者 C2 的直接证据。
// 这是"是否被远程控制"最直接的本地可查证据。
type C2ContactEvidence struct {
	// DNSCacheHits DNS 缓存中发现的 C2 域名解析记录
	DNSCacheHits []string `json:"dns_cache_hits,omitempty"`
	// ActiveConnections 当前仍存活的对 C2 IP/域名的网络连接
	ActiveConnections []string `json:"active_connections,omitempty"`
	// ElectronNetworkHits Apifox Electron Network 缓存目录中发现的 C2 相关文件
	ElectronNetworkHits []FileHit `json:"electron_network_hits,omitempty"`
	// ContactConfirmed 是否确认曾发生 C2 通信
	ContactConfirmed bool `json:"contact_confirmed"`
	// ContactNote 综合说明
	ContactNote string `json:"contact_note,omitempty"`
}

// c2Indicators 是攻击者已知的 C2 域名和 IP，用于多处检测。
var c2Indicators = []string{
	"apifox.it.com",
	"104.21.2.104",
	"172.67.129.21",
}
