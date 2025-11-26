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
	UserAgent            = "AdGuard-HostlistCompiler-Go/1.1" // 请求头
	InvalidDomainsSource = "invalid_domains.txt"             // 本地路径或 URL
	// 上游规则源列表的 URL
	UpstreamListSource = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"
)

// -----------------------------------------------------------------------------
// 正则与核心逻辑
// -----------------------------------------------------------------------------

// strictDomainRegex: 严格的域名白名单正则 (RFC 1035，用于纯域名校验)
var strictDomainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.?$`)

// wildcardRegex: 允许包含通配符的宽泛规则校验 (允许 *, ^, 字母数字, 点, 短横线)
var wildcardRegex = regexp.MustCompile(`^[a-zA-Z0-9\-\.\*\^]+$`)

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
	fmt.Println(">>> 开始执行 AdGuard 规则清洗任务 (Expert Mode)...")

	// 1. 加载无效域名列表
	invalidDomains = loadInvalidDomains(InvalidDomainsSource)
	fmt.Printf(">>> 加载无效域名: %d 条\n", len(invalidDomains))

	// 2. 加载上游规则源列表
	upstreams := loadUpstreams(UpstreamListSource)
	if len(upstreams) == 0 {
		fmt.Println("!!! 未获取到任何上游规则源，程序退出")
		return
	}
	fmt.Printf(">>> 加载上游源列表: %d 个地址\n", len(upstreams))

	// 3. 并发下载所有源
	var wg sync.WaitGroup
	// 限制并发数为 10，防止对上游源造成过大压力或触发限流
	sem := make(chan struct{}, 10)

	for _, url := range upstreams {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}        // 获取令牌
			defer func() { <-sem }() // 释放令牌
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
	// 优化排序：让以 || 开头的规则排在一起，* 开头的排在一起
	sort.Strings(finalRules)

	// 5. 写入最终结果
	if err := writeSliceToFile(OutputFile, finalRules, true); err != nil {
		fmt.Printf("!!! 写入结果文件失败: %v\n", err)
	} else {
		fmt.Printf(">>> 成功生成: %s\n", OutputFile)
	}

	// 6. 写入 Debug 文件
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
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
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
	// 增大 Buffer 防止单行过长报错
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	localRules := []string{}
	localDebug := []string{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 核心清洗函数
		cleaned, isDebug := normalizeLine(line)

		if cleaned != "" {
			// 检查是否需要排除 (无效域名)
			// 注意：对于通配符规则，extractDomain 可能返回空或无法匹配，这是预期的
			domain := extractDomain(cleaned)
			if domain != "" {
				if _, found := invalidDomains[domain]; found {
					continue
				}
			}
			localRules = append(localRules, cleaned)
		} else if isDebug {
			// 限制 debug 日志长度，防止只有一行的垃圾文件撑爆内存
			if len(line) > 200 {
				line = line[:200] + "..."
			}
			localDebug = append(localDebug, fmt.Sprintf("[%s] %s", url, line))
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("!!! 读取流错误 [%s]: %v\n", url, err)
	}

	// 批量加锁写入全局存储
	mutex.Lock()
	for _, r := range localRules {
		validRules[r] = struct{}{}
	}
	debugLines = append(debugLines, localDebug...)
	mutex.Unlock()
}

// normalizeLine 核心白名单清洗逻辑 (已修复: 支持通配符与修剪脏前缀)
func normalizeLine(line string) (string, bool) {
	// 1. 基础清理：空行与注释
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return "", false
	}

	// 2. [关键修复] 移除 URL 协议前缀 (修复 ://ww10.$denyallow 等规则)
	// 很多垃圾列表会包含 http:// 或 :// 开头的规则，去掉前缀后它们可能是有效的
	if strings.HasPrefix(line, "http://") {
		line = strings.TrimPrefix(line, "http://")
	} else if strings.HasPrefix(line, "https://") {
		line = strings.TrimPrefix(line, "https://")
	} else if strings.HasPrefix(line, "://") {
		line = strings.TrimPrefix(line, "://")
	}

	// 3. AdGuard 标准格式直接放行 (||, @@, |, /)
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "|") || strings.HasPrefix(line, "/") {
		if len(line) < 3 {
			return "", true
		}
		return line, false
	}

	lineLower := strings.ToLower(line)

	// 4. Hosts 格式转换 (0.0.0.0 domain)
	if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
		// [关键修复] 快速检测垃圾 URL 字符 (/ ? =)
		// Hosts 文件不支持路径或查询参数，如果有这些字符，说明是垃圾数据
		if strings.ContainsAny(lineLower, "/?=") {
			return "", true
		}

		parts := strings.Fields(lineLower)
		if len(parts) >= 2 {
			domain := parts[1]
			if domain == "localhost" || domain == "local" || domain == "0.0.0.0" || domain == "127.0.0.1" {
				return "", false
			}
			// 验证提取出的域名是否合法
			if strictDomainRegex.MatchString(domain) {
				return "||" + domain + "^", false
			}
			// 支持 IDN (Punycode)
			if strings.HasPrefix(domain, "xn--") {
				return "||" + domain + "^", false
			}
		}
		return "", true
	}

	// 5. [关键修复] 处理纯文本规则 (可能是域名，也可能是通配符 pattern)

	// 分离域名/Pattern 部分和修饰符 (例如 $denyallow)
	patternPart := lineLower
	modifiers := ""
	if idx := strings.Index(lineLower, "$"); idx != -1 {
		patternPart = lineLower[:idx]
		modifiers = lineLower[idx:]
	}
	patternPart = strings.TrimSpace(patternPart)

	// A. 如果包含通配符 * (修复 *factoryoutlet. 等规则)
	if strings.Contains(patternPart, "*") {
		// 简单的合法性检查，防止全是乱码
		if wildcardRegex.MatchString(patternPart) {
			// 如果原始行已经包含了修饰符，我们需要重组它吗？
			// AdGuard 允许直接写 "pattern$opt"，不需要加 ||
			// 但如果用户希望将 *foo.com 变为 ||*foo.com^，通常 pattern 模式建议保持原样作为 URL 规则
			// 或者作为 ||*domain^ 规则。
			// 策略：如果以 . 或 * 开头，或者包含 *，直接返回原始组合 (Lower case)
			return patternPart + modifiers, false
		}
		return "", true // 包含 * 但含有非法字符
	}

	// B. 纯域名格式 (example.com) -> 转为 ||example.com^
	if strictDomainRegex.MatchString(patternPart) {
		return "||" + patternPart + "^" + modifiers, false
	}

	// C. Punycode 域名 (xn--...)
	if strings.HasPrefix(patternPart, "xn--") {
		// 稍微宽松一点的检查，只要不含非法 URL 字符即可
		if !strings.ContainsAny(patternPart, "/?=&") {
			return "||" + patternPart + "^" + modifiers, false
		}
	}

	// D. 仅包含 IP 的情况
	if strictIPRegex.MatchString(patternPart) {
		return "||" + patternPart + "^" + modifiers, false
	}

	return "", true
}

func loadInvalidDomains(source string) map[string]struct{} {
	set := make(map[string]struct{})
	var scanner *bufio.Scanner

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
		f, err := os.Open(source)
		if err != nil {
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
		// 移除可能存在的修饰符
		if idx := strings.Index(domain, "$"); idx != -1 {
			domain = domain[:idx]
		}
		set[domain] = struct{}{}
	}
	return set
}

// extractDomain 辅助提取，用于检查 invalidDomains
func extractDomain(rule string) string {
	ruleLower := strings.ToLower(rule)
	// 移除修饰符
	if idx := strings.Index(ruleLower, "$"); idx != -1 {
		ruleLower = ruleLower[:idx]
	}

	// 简单的 AdGuard 格式提取 ||domain^
	if strings.HasPrefix(ruleLower, "||") && strings.HasSuffix(ruleLower, "^") {
		domain := strings.TrimSuffix(strings.TrimPrefix(ruleLower, "||"), "^")
		// 如果包含 *，这可能不是一个确切的域名，跳过精确匹配检查
		if strings.Contains(domain, "*") {
			return ""
		}
		return domain
	}

	// 如果是纯域名规则 (在 normalize 中未被转换的，虽然 normalize 通常会转换)
	if strictDomainRegex.MatchString(ruleLower) {
		return ruleLower
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
