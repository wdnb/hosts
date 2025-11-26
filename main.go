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
	InvalidDomainsSource = "invalid_domains.txt"             // 本地路径或 URL
	// 新增：上游规则源列表的 URL (每行一个 URL)
	UpstreamListSource = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"
)

// -----------------------------------------------------------------------------
// 正则与核心逻辑
// -----------------------------------------------------------------------------

// domainLabel: 匹配单个域名标签 (如: example, com, 123)
// 允许字母、数字、连字符，但不能以连字符开头或结尾。
// 长度限制 1-63 字符。
const domainLabel = `[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?`

// **strictDomainRegex**: 匹配所有能注册的域名（即至少两级）。
// 匹配 (Label.)+TLD，其中 TLD 可以是 1 个字符或更长，可以包含数字和字母。
// 相比原版，TLD 更加宽松，能匹配新的 gTLD。
var strictDomainRegex = regexp.MustCompile(`^` + domainLabel + `\.(?:` + domainLabel + `\.?)+$`)

// strictIPRegex: 简单的 IPv4 校验
var strictIPRegex = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)

// Global storage
var (
	validRules     = make(map[string]struct{}) // 存储有效规则 (Set)
	debugLines     = make([]string, 0)         // 存储无效行
	invalidDomains = make(map[string]struct{}) // 无效域名 Set
	mutex          sync.Mutex                  // 保护上述两个容器的并发写入
)

func main() {
	start := time.Now()
	fmt.Println(">>> 开始执行 AdGuard 规则清洗任务...")

	// 1. 加载无效域名列表
	invalidDomains = loadInvalidDomains(InvalidDomainsSource)
	fmt.Printf(">>> 加载无效域名: %d 条\n", len(invalidDomains))

	// 2. 加载上游规则源列表 (变更点)
	upstreams := loadUpstreams(UpstreamListSource)
	if len(upstreams) == 0 {
		fmt.Println("!!! 未获取到任何上游规则源，程序退出")
		return
	}
	fmt.Printf(">>> 加载上游源列表: %d 个地址\n", len(upstreams))

	// 3. 并发下载所有源
	var wg sync.WaitGroup
	for _, url := range upstreams {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			processURL(u)
		}(url)
	}
	wg.Wait()
	fmt.Printf(">>> 下载与清洗完成。有效规则: %d, 脏数据: %d\n", len(validRules), len(debugLines))
	fmt.Println(">>> 正在排序并写入文件...")

	// 4. 转换为切片以便排序
	finalRules := make([]string, 0, len(validRules))
	for rule := range validRules {
		finalRules = append(finalRules, rule)
	}
	sort.Strings(finalRules) // 字典序排序

	// 5. 写入最终结果
	if err := writeSliceToFile(OutputFile, finalRules, true); err != nil {
		fmt.Printf("!!! 写入结果文件失败: %v\n", err)
	} else {
		fmt.Printf(">>> 成功生成: %s\n", OutputFile)
	}

	// 6. 写入 Debug 文件 (如果有)
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

// loadUpstreams 从 URL 获取上游规则列表 (保持不变)
func loadUpstreams(url string) []string {
	fmt.Printf("正在获取上游列表: %s\n", url)
	var list []string
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("!!! 获取上游列表失败: %v\n", err)
		return list
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("!!! 获取上游列表 HTTP 错误: %d\n", resp.StatusCode)
		return list
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 忽略空行和注释
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		// 简单的 URL 校验
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			list = append(list, line)
		}
	}

	return list
}

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
			if domain != "" {
				if _, found := invalidDomains[domain]; found {
					continue
				}
			}
			localRules = append(localRules, cleaned)
		} else if isDebug {
			localDebug = append(localDebug, fmt.Sprintf("[%s] %s", url, line)) // 记录来源
		}
	}

	// 批量加锁写入全局存储
	mutex.Lock()
	for _, r := range localRules {
		validRules[r] = struct{}{}
	}
	debugLines = append(debugLines, localDebug...)
	mutex.Unlock()
}

// normalizeLine 核心白名单清洗逻辑 (KISS 优化 Hosts 格式处理)
func normalizeLine(line string) (string, bool) {
	// 1. 空行与注释
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return "", false
	}

	// 2. 显式脏数据拦截
	if strings.HasPrefix(line, "://") || strings.HasPrefix(line, "<") {
		return "", true
	}

	// 3. AdGuard 标准格式
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "|") || strings.HasPrefix(line, "/") {
		if len(line) < 3 { // 避免匹配 ||, | 等无效规则
			return "", true
		}
		return line, false
	}

	lineLower := strings.ToLower(line)

	// 4. Hosts 格式转换 (KISS 优化: 仅检查前缀和字段数量，不再重复检查 IP)
	if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
		parts := strings.Fields(lineLower)
		if len(parts) >= 2 {
			domain := parts[1]
			// 排除本地环回地址
			if domain == "localhost" || domain == "local" || domain == "0.0.0.0" || domain == "127.0.0.1" || domain == "::1" {
				return "", false
			}
			// 验证域名是否合法
			if strictDomainRegex.MatchString(domain) {
				return "||" + domain + "^", false
			}
		}
		return "", true // 格式不符合或域名不合法，视为脏数据
	}

	// 5. 纯域名/IP 格式
	// 纯域名: 直接转换为 AdGuard 格式
	if strictDomainRegex.MatchString(lineLower) {
		return "||" + lineLower + "^", false
	}
	// 纯 IP: 直接转换为 AdGuard 格式
	if strictIPRegex.MatchString(lineLower) {
		return "||" + lineLower + "^", false
	}

	return "", true // 无法识别的行
}

// loadInvalidDomains 加载无效域名列表 (保持不变)
func loadInvalidDomains(source string) map[string]struct{} {
	set := make(map[string]struct{})
	var scanner *bufio.Scanner

	// 检查是否是 URL
	if strings.HasPrefix(strings.ToLower(source), "http://") || strings.HasPrefix(strings.ToLower(source), "https://") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			fmt.Printf("!!! 加载无效域名失败: %v\n", err)
			return set
		}
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)
	} else {
		// 否则是本地文件
		f, err := os.Open(source)
		if err != nil {
			// 文件不存在是正常情况，不一定要报错，返回空集即可，但也打印一下
			fmt.Printf(">>> 无本地无效域名文件，跳过 (%v)\n", err)
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

// extractDomain 辅助提取 (保持不变)
func extractDomain(rule string) string {
	ruleLower := strings.ToLower(rule)
	// 仅尝试提取 ||domain^ 格式的域名
	if strings.HasPrefix(ruleLower, "||") && strings.HasSuffix(ruleLower, "^") {
		domain := strings.TrimSuffix(strings.TrimPrefix(ruleLower, "||"), "^")
		if strictDomainRegex.MatchString(domain) {
			return domain
		}
	}
	return ""
}

func writeSliceToFile(filename string, lines []string, isResult bool) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	if isResult {
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
