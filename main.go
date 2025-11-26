package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
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

// Global storage
var (
	validRules     = make(map[string]struct{}) // 存储有效规则 (Set)
	debugLines     = make([]string, 0)         // 存储未识别行 (原样收入但需调试)
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
	// 限制并发数为 10
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

	fmt.Printf(">>> 下载与清洗完成。有效规则: %d, 未识别行: %d\n", len(validRules), len(debugLines))
	fmt.Println(">>> 正在排序并写入文件...")

	// 4. 转换为切片以便排序
	finalRules := make([]string, 0, len(validRules))
	for rule := range validRules {
		finalRules = append(finalRules, rule)
	}
	sort.Strings(finalRules)

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
			fmt.Printf(">>> 未识别行已备份至: %s\n", DebugFile)
		}
	}

	fmt.Printf(">>> 全部完成，总耗时: %v\n", time.Since(start))
}

// -----------------------------------------------------------------------------
// 辅助函数
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
		cleaned, isUnrecognized := normalizeLine(line)

		if cleaned != "" {
			// 检查是否需要排除 (无效域名)
			domain := extractDomain(cleaned)
			if domain != "" {
				if _, found := invalidDomains[domain]; found {
					continue
				}
			}
			localRules = append(localRules, cleaned)
		}
		if isUnrecognized {
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

// normalizeLine: 简化规则规范化逻辑 (KISS: 优先检测 AdGuard 格式，直接收入；Hosts 转换；域名/IP 转换；通配/非标尝试转换；剩余原样 + 标记未识别)
func normalizeLine(line string) (string, bool) {
	if line == "" {
		return "", false
	}

	// 跳过注释
	if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return "", false
	}

	origLine := line // 保留原始
	line = strings.TrimSpace(strings.ToLower(line))

	// 移除协议前缀 (如果有)
	if strings.HasPrefix(line, "http://") {
		line = line[7:]
	} else if strings.HasPrefix(line, "https://") {
		line = line[8:]
	} else if strings.HasPrefix(line, "://") {
		line = line[3:]
	}

	// 直接放行 AdGuard 官方推荐格式 (||, @@, |, / 开头，最小长度 3)
	if len(line) >= 3 && (strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "|") || strings.HasPrefix(line, "/")) {
		return origLine, false
	}

	// 处理 Hosts 格式 (转换为 AdGuard 格式)
	if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
		parts := strings.Fields(line)
		if len(parts) < 2 || strings.ContainsAny(line, "/?=&") {
			return "", true // 脏数据，标记未识别 (但这里视作未识别，原样? 否，按需求脏数据只debug不收入)
		}
		domain := parts[1]
		if domain == "localhost" || domain == "local" || domain == "0.0.0.0" || domain == "127.0.0.1" {
			return "", false
		}
		normalizedDomain, err := normalizeDomain(domain)
		if err == nil {
			return "||" + normalizedDomain + "^", false
		}
		return "", true // 无效 Hosts，标记未识别
	}

	// 分离修饰符 ($...)
	modifiers := ""
	if idx := strings.Index(line, "$"); idx != -1 {
		modifiers = origLine[idx:] // 使用 origLine 以保留大小写
		line = line[:idx]
		origLine = origLine[:idx]
	}

	// 统一移除尾部 '^' (如果存在)
	pattern := strings.TrimSuffix(line, "^")

	// 移除前导 '.' 或 '-'或 '*'
	pattern = strings.TrimLeft(pattern, ".-*")

	if pattern == "" {
		return "", true // 空，标记未识别
	}

	// 处理通配符规则 (允许 *，^，:，_ 等；转换为 AdGuard 格式)
	if strings.Contains(pattern, "*") {
		// 简单校验: 只含允许字符
		if strings.ContainsAny(pattern, "!@#%&()=[]{}\\|;'\",<>?`~") {
			return origLine + modifiers, true // 复杂通配，原样 + 未识别
		}
		prefix := "||"
		origPattern := strings.TrimSuffix(strings.ToLower(origLine), strings.ToLower(modifiers)) // 同步 orig
		if strings.HasPrefix(pattern, "*") {
			origPattern = strings.TrimPrefix(origPattern, "*")
			pattern = strings.TrimPrefix(pattern, "*")
			prefix = "||*"
		}
		// 尝试规范化域名部分
		normalizedPattern, err := normalizeDomain(pattern)
		if err == nil {
			return prefix + normalizedPattern + "^" + modifiers, false
		}
		return prefix + origPattern + "^" + modifiers, false // 仍转换，但不保证
	}

	// 处理纯域名或 IP (使用库规范化，支持 punycode 和非标)
	normalized, err := normalizeDomain(pattern)
	if err == nil {
		return "||" + normalized + "^" + modifiers, false
	}
	if ip := net.ParseIP(pattern); ip != nil { //ip不要了
		return origLine, true
		// return "||" + pattern + "^" + modifiers, false
	}

	// 非标准规则: 尝试作为域名处理 (宽松，支持 _ 等)
	if strings.ContainsAny(pattern, "abcdefghijklmnopqrstuvwxyz0123456789-._:") && !strings.ContainsAny(pattern, "!@#%&()=[]{}\\|;'\",<>?`~/=*") {
		normalized, err = idna.ToASCII(pattern) // 尝试 punycode 转换
		if err == nil && normalized != "" {
			return origLine, true
			// return "||" + normalized + "^" + modifiers, false
		}
	}

	// 剩余不能匹配的: 原样返回，并标记未识别
	return origLine, true
}

// normalizeDomain: 使用 idna 库处理 punycode 和简单校验 (支持 _ 等非标)
func normalizeDomain(domain string) (string, error) {
	// 转换为 Punycode (ASCII)
	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return "", err
	}
	// 简单校验: 至少一个 .，字母数字 - _ . 组成，TLD 至少 2 位 (宽松，支持非标)
	if !strings.Contains(asciiDomain, ".") || len(asciiDomain) < 4 || strings.ContainsAny(asciiDomain, "!@#%&()=[]{}\\|;'\",<>?`~/*:^") {
		return "", fmt.Errorf("invalid domain")
	}
	return asciiDomain, nil
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
		if idx := strings.Index(domain, "$"); idx != -1 {
			domain = domain[:idx]
		}
		set[domain] = struct{}{}
	}
	return set
}

func extractDomain(rule string) string {
	ruleLower := strings.ToLower(rule)
	if idx := strings.Index(ruleLower, "$"); idx != -1 {
		ruleLower = ruleLower[:idx]
	}

	if strings.HasPrefix(ruleLower, "||") && strings.HasSuffix(ruleLower, "^") {
		domain := strings.TrimSuffix(strings.TrimPrefix(ruleLower, "||"), "^")
		if strings.Contains(domain, "*") {
			// 对于通配符，提取不带 * 的纯域名部分
			trimmedDomain := strings.TrimPrefix(domain, "*")
			if !strings.Contains(trimmedDomain, "*") {
				_, err := normalizeDomain(trimmedDomain)
				if err == nil {
					return trimmedDomain
				}
			}
			return ""
		}
		return domain
	}

	_, err := normalizeDomain(ruleLower)
	if err == nil {
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
		fmt.Fprintln(w, "# Debug: Unrecognized lines (included as-is in output)")
		fmt.Fprintf(w, "# Generated: %s\n", time.Now().Format(time.RFC3339))
	}

	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
