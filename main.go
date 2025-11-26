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
	DebugFile            = "adblock_debug_unrecognized.txt"  // 未识别、低效、冗余规则等
	UserAgent            = "AdGuard-HostlistCompiler-Go/1.1" // 请求头
	InvalidDomainsSource = "invalid_domains.txt"             // 本地路径或 URL
	// 上游规则源列表的 URL
	UpstreamListSource = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"
)

// Global storage
var (
	validRules     = make(map[string]struct{}) // 存储有效高效规则 (Set，去重)
	debugLines     = make([]string, 0)         // 存储未识别、低效或不符合行
	invalidDomains = make(map[string]struct{}) // 无效域名 Set
	mutex          sync.Mutex                  // 保护并发写入
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
	sem := make(chan struct{}, 10) // 限制并发数为 10

	for _, url := range upstreams {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			processURL(u)
		}(url)
	}
	wg.Wait()

	fmt.Printf(">>> 下载与清洗完成。有效规则: %d, 未识别/低效行: %d\n", len(validRules), len(debugLines))
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
			fmt.Printf(">>> 未识别/低效行已备份至: %s\n", DebugFile)
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
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	localRules := []string{}
	localDebug := []string{}

	for scanner.Scan() {
		origLine := scanner.Text()
		line := strings.TrimSpace(origLine)

		// 核心清洗函数
		cleaned, isDebug := normalizeLine(line, origLine)

		if cleaned != "" {
			// 检查无效域名
			domain := extractDomain(cleaned)
			if domain != "" {
				if _, found := invalidDomains[domain]; found {
					continue
				}
			}
			localRules = append(localRules, cleaned)
		}
		if isDebug {
			if len(origLine) > 200 {
				origLine = origLine[:200] + "..."
			}
			localDebug = append(localDebug, fmt.Sprintf("[%s] %s", url, origLine))
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("!!! 读取流错误 [%s]: %v\n", url, err)
	}

	// 批量写入全局 (Set 自动去重)
	mutex.Lock()
	for _, r := range localRules {
		validRules[r] = struct{}{}
	}
	debugLines = append(debugLines, localDebug...)
	mutex.Unlock()
}

// normalizeLine: 只保留高效纯域名阻塞规则 (||domain^)，淘汰其他不符合/低效/冗余
func normalizeLine(line, origLine string) (string, bool) {
	if line == "" {
		return "", false
	}

	// 跳过注释
	if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return "", false
	}

	lowerLine := strings.ToLower(line)

	// 移除协议前缀
	if strings.HasPrefix(lowerLine, "http://") {
		lowerLine = lowerLine[7:]
		origLine = origLine[7:]
	} else if strings.HasPrefix(lowerLine, "https://") {
		lowerLine = lowerLine[8:]
		origLine = origLine[8:]
	} else if strings.HasPrefix(lowerLine, "://") {
		lowerLine = lowerLine[3:]
		origLine = origLine[3:]
	}

	// 淘汰低效: 正则、@@、| (非||)、$modifiers、通配*、IP 等
	if strings.Contains(lowerLine, "/") || strings.Contains(lowerLine, "@@") ||
		(strings.HasPrefix(lowerLine, "|") && !strings.HasPrefix(lowerLine, "||")) ||
		strings.Contains(lowerLine, "$") || strings.Contains(lowerLine, "*") ||
		net.ParseIP(lowerLine) != nil {
		return "", true
	}

	// 处理 Hosts 格式 (仅纯域名)
	if strings.HasPrefix(lowerLine, "0.0.0.0 ") || strings.HasPrefix(lowerLine, "127.0.0.1 ") {
		parts := strings.Fields(lowerLine)
		if len(parts) < 2 || strings.ContainsAny(lowerLine, "/?=&") {
			return "", true
		}
		domain := parts[1]
		if domain == "localhost" || domain == "local" || domain == "0.0.0.0" || domain == "127.0.0.1" {
			return "", false
		}
		normalizedDomain, err := normalizeDomain(domain)
		if err == nil {
			return "||" + normalizedDomain + "^", false
		}
		return "", true
	}

	// 处理 AdGuard ||domain^ 格式 (仅纯域名，无modifiers/通配)
	if strings.HasPrefix(lowerLine, "||") && strings.HasSuffix(lowerLine, "^") && len(lowerLine) >= 5 {
		domain := strings.TrimSuffix(strings.TrimPrefix(lowerLine, "||"), "^")
		normalizedDomain, err := normalizeDomain(domain)
		if err == nil && !strings.ContainsAny(domain, "/*$@|") {
			return "||" + normalizedDomain + "^", false
		}
		return "", true
	}

	// 处理纯域名 (转换为 ||domain^)
	normalized, err := normalizeDomain(lowerLine)
	if err == nil {
		return "||" + normalized + "^", false
	}

	// 剩余淘汰
	return "", true
}

// normalizeDomain: 处理 punycode 和校验 (宽松支持非标)
func normalizeDomain(domain string) (string, error) {
	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return "", err
	}
	if !strings.Contains(asciiDomain, ".") || len(asciiDomain) < 4 || strings.ContainsAny(asciiDomain, "!@#%&()=[]{}\\|;'\",<>?`~/*:^$") {
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
	if strings.HasPrefix(ruleLower, "||") && strings.HasSuffix(ruleLower, "^") {
		domain := strings.TrimSuffix(strings.TrimPrefix(ruleLower, "||"), "^")
		_, err := normalizeDomain(domain)
		if err == nil {
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
		fmt.Fprintln(w, "! Title: Optimized AdGuard Home Blocklist (Efficient Domains Only)")
		fmt.Fprintf(w, "! Updated: %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(w, "! Total count: %d\n", len(lines))
		fmt.Fprintln(w, "!")
	} else {
		fmt.Fprintln(w, "# Debug: Unrecognized, inefficient, or non-conforming lines")
		fmt.Fprintf(w, "# Generated: %s\n", time.Now().Format(time.RFC3339))
	}

	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
