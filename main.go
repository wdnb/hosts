package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// 配置区域
// -----------------------------------------------------------------------------

const (
	OutputFile           = "adblock_aggr_optimized.txt"      // 输出的规则文件
	DebugFile            = "adblock_debug_unrecognized.txt"  // 被清洗掉的脏数据
	UserAgent            = "AdGuard-HostlistCompiler-Go/1.0" // 请求头
	InvalidDomainsSource = "invalid_domains.txt"             // 可以是本地路径或 GitHub URL (e.g., "https://raw.githubusercontent.com/user/repo/main/invalid_domains.txt")
)

// Upstreams 上游规则源列表
// 可以在这里添加任意 URL，程序会自动并发下载
var Upstreams = []string{
	"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt", //217heidai
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",                  // AdAway Default Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt",                 // 1Hosts (Lite)
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",                 // AdGuard DNS Popup Hosts filter
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt",                 // HaGeZi's Ultimate Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",                 // OISD Blocklist Big
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",                  // Peter Lowe's Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_69.txt",                 // ShadowWhisperer Tracking List
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt",                 // Dandelion Sprout's Anti Push Notifications
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt",                  // Dandelion Sprout's Game Console Adblock List
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_45.txt",                 // HaGeZi's Allowlist Referral
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt",                 // HaGeZi's Apple Tracker Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt",                 // HaGeZi's Gambling Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt",                 // HaGeZi's OPPO & Realme Tracker Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",                 // Malicious URL Blocklist (URLHaus)
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt",                 // HaGeZi's Samsung Tracker Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",                 // uBlock₀ filters – Badware risks
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",                  // The Big List of Hacked Malware Web Sites
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",                 // Stalkerware Indicators List
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",                 // ShadowWhisperer's Malware List
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",                 // Scam Blocklist by DurableNapkin
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt",                 // HaGeZi's Vivo Tracker Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",                 // Phishing Army
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",                 // HaGeZi's Windows/Office Tracker Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt",                 // HaGeZi's Xiaomi Tracker Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",                  // NoCoin Filter List
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",                  // Perflyst and Dandelion Sprout's Smart-TV Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt",                 // HaGeZi's Threat Intelligence Feeds
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt",                 // HaGeZi's The World's Most Abused TLDs
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt",                 // ShadowWhisperer's Dating List
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",                 // HaGeZi's DynDNS Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_71.txt",                 // HaGeZi's DNS Rebind Protection
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",                 // HaGeZi's Badware Hoster Blocklist
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt",                 // CHN: anti-AD
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",                 // Dandelion Sprout's Anti-Malware List
	"https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",                 // Phishing URL Blocklist (PhishTank and OpenPhish)
}

// -----------------------------------------------------------------------------
// 正则与核心逻辑
// -----------------------------------------------------------------------------

// strictDomainRegex: 严格的域名白名单正则 (RFC 1035)
// 用于判断一行文本是否为“纯域名”。必须包含至少一个点，且后缀至少2位字母。
var strictDomainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// strictIPRegex: 简单的 IPv4 校验，用于将纯 IP 转换为 AdGuard 格式
var strictIPRegex = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)

// Global storage
// 使用 Map 的 Key 进行天然去重
var (
	validRules     = make(map[string]struct{}) // 存储有效规则 (Set)
	debugLines     = make([]string, 0)         // 存储无效行
	invalidDomains = make(map[string]struct{}) // 无效域名 Set
	mutex          sync.Mutex                  // 保护上述两个容器的并发写入
)

func main() {
	start := time.Now()
	fmt.Println(">>> 开始执行 AdGuard 规则清洗任务...")

	// 加载无效域名列表
	invalidDomains = loadInvalidDomains(InvalidDomainsSource)
	fmt.Printf(">>> 加载无效域名: %d 条\n", len(invalidDomains))

	// 1. 并发下载所有源
	var wg sync.WaitGroup
	for _, url := range Upstreams {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			processURL(u)
		}(url)
	}
	wg.Wait()

	fmt.Printf(">>> 下载与清洗完成。有效规则: %d, 脏数据: %d\n", len(validRules), len(debugLines))
	fmt.Println(">>> 正在排序并写入文件...")

	// 2. 转换为切片以便排序
	finalRules := make([]string, 0, len(validRules))
	for rule := range validRules {
		finalRules = append(finalRules, rule)
	}
	sort.Strings(finalRules) // 字典序排序

	// 3. 写入最终结果
	if err := writeSliceToFile(OutputFile, finalRules, true); err != nil {
		fmt.Printf("!!! 写入结果文件失败: %v\n", err)
	} else {
		fmt.Printf(">>> 成功生成: %s\n", OutputFile)
	}

	// 4. 写入 Debug 文件 (如果有)
	if len(debugLines) > 0 {
		sort.Strings(debugLines)
		if err := writeSliceToFile(DebugFile, debugLines, false); err != nil {
			fmt.Printf("!!! 写入Debug文件失败: %v\n", err)
		} else {
			fmt.Printf(">>> 脏数据已备份至: %s\n", DebugFile)
		}
	}

	fmt.Printf(">>> 全部完成，总耗时: %v\n", time.Since(start))
}

// -----------------------------------------------------------------------------
// 处理逻辑
// -----------------------------------------------------------------------------

func processURL(url string) {
	fmt.Printf("正在下载: %s\n", url)

	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("!!! 下载失败 [%s]: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("!!! HTTP 错误 [%s]: %d\n", url, resp.StatusCode)
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	localRules := []string{}
	localDebug := []string{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 核心清洗函数
		cleaned, isDebug := normalizeLine(line)

		if cleaned != "" {
			// 检查是否需要排除 (无效域名)
			domain := extractDomain(cleaned)
			//使用 _, found := map[key] 检查 key 是否存在
			if domain != "" {
				if _, found := invalidDomains[domain]; found {
					// 直接排除，不计入 Debug
					continue
				}
			}
			localRules = append(localRules, cleaned)
		} else if isDebug {
			localDebug = append(localDebug, fmt.Sprintf("[%s] %s", url, line)) // 记录来源
		}
	}

	// 批量加锁写入全局存储，减少锁竞争
	mutex.Lock()
	for _, r := range localRules {
		validRules[r] = struct{}{} // Map 自动去重
	}
	debugLines = append(debugLines, localDebug...)
	mutex.Unlock()
}

// normalizeLine 核心白名单清洗逻辑
// 返回: (清洗后的规则, 是否为脏数据)
func normalizeLine(line string) (string, bool) {
	// 1. 空行与注释：直接丢弃，不算 Debug
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return "", false
	}

	// 2. 显式脏数据拦截 (Blacklist Check)
	// 拦截 broken URLs (e.g., "://ww4.")
	if strings.HasPrefix(line, "://") {
		return "", true
	}
	// 拦截 HTML 标签
	if strings.HasPrefix(line, "<") {
		return "", true
	}

	// 3. AdGuard 标准格式白名单 (Whitelist Check - AdGuard Native)
	// 如果行以这些符号开头，我们假设它是合法的 AdGuard 规则，予以保留。
	// || = 域名拦截, @@ = 白名单, | = 锚点, / = 正则
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "|") || strings.HasPrefix(line, "/") {
		// 再次检查是否包含明显错误（如空格），但 AdGuard 修饰符中可能包含空格吗？
		// 严格来说，AdGuard 规则体中间不应有空格，除非是在 Regex 或特定的 value 中。
		// 为了 KISS，我们信任以这些符号开头的行，除非它非常短。
		if len(line) < 3 {
			return "", true
		}
		return line, false
	}

	lineLower := strings.ToLower(line)

	// 4. Hosts 格式转换 (Whitelist Check - Hosts)
	// 匹配 "0.0.0.0 domain.com" 或 "127.0.0.1 domain.com"
	if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
		parts := strings.Fields(lineLower)
		if len(parts) >= 2 {
			domain := parts[1]
			// 排除 localhost
			if domain == "localhost" || domain == "local" || domain == "0.0.0.0" || domain == "127.0.0.1" {
				return "", false
			}
			// 验证提取的部分是否真的是域名
			if strictDomainRegex.MatchString(domain) {
				return "||" + domain + "^", false
			}
		}
		// 是Hosts格式但域名无效 -> Debug
		return "", true
	}

	// 5. 纯域名/IP 格式转换 (Whitelist Check - Pure Domain/IP)
	// 必须严格匹配域名正则，防止误判
	if strictDomainRegex.MatchString(lineLower) {
		return "||" + lineLower + "^", false
	}
	if strictIPRegex.MatchString(lineLower) {
		return "||" + lineLower + "^", false
	}

	// 6. 兜底：所有未命中上述白名单的行，全部视为 Debug
	return "", true
}

// loadInvalidDomains 加载无效域名列表，支持本地文件或 URL
func loadInvalidDomains(source string) map[string]struct{} {
	set := make(map[string]struct{})
	var scanner *bufio.Scanner

	if strings.HasPrefix(strings.ToLower(source), "http://") || strings.HasPrefix(strings.ToLower(source), "https://") {
		// 从 URL 下载
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			fmt.Printf("!!! 加载无效域名失败 (URL: %s): %v\n", source, err)
			return set
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			fmt.Printf("!!! HTTP 错误加载无效域名 (URL: %s): %d\n", source, resp.StatusCode)
			return set
		}
		scanner = bufio.NewScanner(resp.Body)
	} else {
		// 本地文件
		f, err := os.Open(source)
		if err != nil {
			fmt.Printf("!!! 打开无效域名文件失败 (%s): %v\n", source, err)
			return set
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		domain := strings.ToLower(line)
		if strictDomainRegex.MatchString(domain) {
			set[domain] = struct{}{}
		}
	}
	return set
}

// extractDomain 从简单规则中提取域名 (仅针对 ||domain^ 格式)
func extractDomain(rule string) string {
	ruleLower := strings.ToLower(rule)
	if strings.HasPrefix(ruleLower, "||") && strings.HasSuffix(ruleLower, "^") {
		domain := strings.TrimSuffix(strings.TrimPrefix(ruleLower, "||"), "^")
		if strictDomainRegex.MatchString(domain) {
			return domain
		}
	}
	return ""
}

// -----------------------------------------------------------------------------
// 辅助工具
// -----------------------------------------------------------------------------

func writeSliceToFile(filename string, lines []string, isResult bool) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	if isResult {
		// 写入 AdGuard 头部信息
		fmt.Fprintln(w, "! Title: Optimized AdGuard Home Blocklist")
		fmt.Fprintf(w, "! Updated: %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(w, "! Total count: %d\n", len(lines))
		fmt.Fprintln(w, "!")
	} else {
		fmt.Fprintln(w, "# Debug: Unrecognized lines / Dirty data")
		fmt.Fprintf(w, "# Generated: %s\n", time.Now().Format(time.RFC3339))
	}

	for _, line := range lines {
		fmt.Fprintln(w, line)
	}

	return w.Flush()
}
