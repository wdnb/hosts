package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

// -----------------------------------------------------------------------------
// 配置与常量
// -----------------------------------------------------------------------------

const (
	OutputFile         = "adblock_lite.txt"
	DebugFile          = "adblock_debug.txt"
	InvalidDomainsFile = "invalid_domains.txt" // 本地文件，一行一个域名
	UserAgent          = "AdGuard-Compiler/4.0 (Go 1.23; Advanced Pruning)"
	MaxGoroutines      = 16
	UpstreamListSource = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"
)

// 允许的字符：字母、数字、点、横杠、下划线、星号(通配符)
var validRulePattern = regexp.MustCompile(`^[a-z0-9.\-_*]+$`)

// -----------------------------------------------------------------------------
// 类型定义
// -----------------------------------------------------------------------------

// DebugEntry 记录调试信息
type DebugEntry struct {
	Source string
	Line   string
	Reason string
}

// -----------------------------------------------------------------------------
// 主程序
// -----------------------------------------------------------------------------

func main() {
	start := time.Now()
	printHeader()

	// 0. 加载排除域名列表
	invalidSet := loadInvalidDomains(InvalidDomainsFile)

	// 1. 获取上游
	urls := fetchUpstreamList(UpstreamListSource)
	if len(urls) == 0 {
		fmt.Println("!!! 未获取到上游源，退出")
		return
	}

	// 2. 并发下载与清洗
	var (
		rawRules = make(map[string]struct{})
		debugLog = make([]DebugEntry, 0)
		mu       sync.Mutex
		wg       sync.WaitGroup
	)

	sem := make(chan struct{}, MaxGoroutines)
	totalUrls := len(urls)

	fmt.Printf(">>> [Phase 1] 开始并发下载 %d 个源...\n", totalUrls)

	for i, url := range urls {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// 实时进度打印
			if idx > 0 && idx%5 == 0 {
				fmt.Printf("    -> 下载进度: %d/%d (总耗时: %v)\n", idx, totalUrls, time.Since(start).Round(time.Second))
			}

			// 下载并解析，传入 invalidSet 进行过滤
			valid, invalid := downloadAndProcess(u, invalidSet)

			mu.Lock()
			for _, r := range valid {
				rawRules[r] = struct{}{}
			}
			// 仅记录前 100万 条错误日志，防止内存溢出
			if len(debugLog) < 1000000 {
				debugLog = append(debugLog, invalid...)
			}
			mu.Unlock()
		}(i, url)
	}
	wg.Wait()

	printMemUsage()
	totalRaw := len(rawRules)
	fmt.Printf(">>> [Phase 1 Done] 初筛后规则总数: %d | 耗时: %v\n", totalRaw, time.Since(start))

	// 3. 分类与深度优化 (压缩核心)
	fmt.Println(">>> [Phase 2] 执行高级规则优化 (通配符剪枝 & 子域名剔除)...")

	wildcards := make([]string, 0)
	exacts := make([]string, 0)

	for r := range rawRules {
		if strings.Contains(r, "*") {
			wildcards = append(wildcards, r)
		} else {
			exacts = append(exacts, r)
		}
	}

	optStart := time.Now()

	// 3a. 通配符剪枝 (解决通配符对纯域名的覆盖问题)
	remainingExacts, wildcardPrunedCount := wildcardPruning(exacts, wildcards)

	// 3b. 子域名剔除 (解决父域名对子域名的覆盖问题)
	optimizedExacts, subdomainPrunedCount := removeSubdomains(remainingExacts)

	totalPruned := wildcardPrunedCount + subdomainPrunedCount

	fmt.Printf("    -> 优化算法总耗时: %v\n", time.Since(optStart))
	fmt.Printf("    -> 1. 通配符剪枝剔除: %d 条\n", wildcardPrunedCount)
	fmt.Printf("    -> 2. 子域名剔除剔除: %d 条\n", subdomainPrunedCount)
	fmt.Printf("    -> 总优化剔除: %d 条 (最终规则数: %d)\n", totalPruned, len(wildcards)+len(optimizedExacts))

	// 4. 生成最终结果
	fmt.Println(">>> [Phase 3] 生成文件...")
	finalList := make([]string, 0, len(wildcards)+len(optimizedExacts))

	// 重组为 AdGuard 格式
	for _, w := range wildcards {
		finalList = append(finalList, fmt.Sprintf("||%s^", w))
	}
	for _, e := range optimizedExacts {
		finalList = append(finalList, fmt.Sprintf("||%s^", e))
	}
	sort.Strings(finalList)

	// 5. 写入
	writeResultFile(OutputFile, finalList)
	writeDebugFile(DebugFile, debugLog)

	fmt.Println("---------------------------------------------------------")
	fmt.Printf(">>> 全部完成!\n")
	fmt.Printf(">>> 最终规则数: %d\n", len(finalList))
	fmt.Printf(">>> 总耗时: %v\n", time.Since(start))
	fmt.Println("---------------------------------------------------------")
}

// -----------------------------------------------------------------------------
// 压缩算法 V2: 通配符剪枝
// -----------------------------------------------------------------------------

// wildcardPruning: 剔除被通配符规则完全覆盖的纯域名规则。
func wildcardPruning(exacts []string, wildcards []string) ([]string, int) {
	if len(wildcards) == 0 {
		return exacts, 0
	}

	exactMap := make(map[string]struct{})
	for _, e := range exacts {
		exactMap[e] = struct{}{}
	}

	removedCount := 0

	for _, exact := range exacts {
		if _, ok := exactMap[exact]; !ok {
			continue
		}

		for _, pattern := range wildcards {
			if isCoveredByWildcard(exact, pattern) {
				delete(exactMap, exact) // 移除冗余的 exact 域名
				removedCount++
				break // 找到一个匹配的通配符即可
			}
		}
	}

	remainingExacts := make([]string, 0, len(exactMap))
	for e := range exactMap {
		remainingExacts = append(remainingExacts, e)
	}

	return remainingExacts, removedCount
}

// isCoveredByWildcard 检查一个纯域名是否能被通配符模式覆盖。
func isCoveredByWildcard(exact string, pattern string) bool {
	// 1. 拆分模式：例如 "*-analytics*.huami.com" -> ["", "-analytics", ".huami.com"]
	parts := strings.Split(pattern, "*")
	idx := 0 // 记录在 exact 字符串中匹配到的位置

	// 2. 检查前缀 (parts[0])
	if parts[0] != "" {
		if !strings.HasPrefix(exact, parts[0]) {
			return false
		}
		idx = len(parts[0])
	}

	// 3. 检查中间部分 (parts[1] 到 parts[len-2]) 必须按顺序出现
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" {
			continue // 处理 ** 或 *.* 这种连续通配符
		}

		foundIdx := strings.Index(exact[idx:], part)
		if foundIdx == -1 {
			return false // 中间部分未找到
		}
		idx += foundIdx + len(part)
	}

	// 4. 检查后缀 (parts[len-1])
	lastPart := parts[len(parts)-1]
	if lastPart != "" {
		if !strings.HasSuffix(exact, lastPart) {
			return false
		}
	} else if len(parts) > 1 && idx > len(exact) {
		return false
	}

	return true
}

// -----------------------------------------------------------------------------
// 核心逻辑 (清洗与校验)
// -----------------------------------------------------------------------------

func downloadAndProcess(url string, invalidSet map[string]struct{}) (valid []string, invalid []DebugEntry) {
	client := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		invalid = append(invalid, DebugEntry{Source: url, Line: "Network", Reason: err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		invalid = append(invalid, DebugEntry{Source: url, Line: "Status", Reason: fmt.Sprint(resp.StatusCode)})
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}

		clean, reason := normalizeLine(line)

		if clean == "" {
			if len(line) > 5 {
				invalid = append(invalid, DebugEntry{Source: url, Line: trimLong(line), Reason: reason})
			}
			continue
		}

		// 检查: 是否在无效域名黑名单中
		if _, exists := invalidSet[clean]; exists {
			invalid = append(invalid, DebugEntry{Source: url, Line: clean, Reason: "Blocked by invalid_domains"})
			continue
		}

		valid = append(valid, clean)
	}
	return
}

func normalizeLine(line string) (string, string) {
	lower := strings.ToLower(line)
	// 1. 修饰符截断
	if before, _, found := strings.Cut(lower, "$"); found {
		lower = strings.TrimSpace(before)
	}

	// 2. 协议及IP剥离 (Go 1.20+ CutPrefix)
	for {
		var found bool
		if lower, found = strings.CutPrefix(lower, "http://"); found {
			continue
		}
		if lower, found = strings.CutPrefix(lower, "https://"); found {
			continue
		}
		if lower, found = strings.CutPrefix(lower, "0.0.0.0 "); found {
			continue
		}
		if lower, found = strings.CutPrefix(lower, "127.0.0.1 "); found {
			continue
		}
		if lower, found = strings.CutPrefix(lower, "::1 "); found {
			continue
		}
		break
	}
	lower = strings.TrimSpace(lower)

	// 3. AdGuard 语法清理
	if val, found := strings.CutPrefix(lower, "||"); found {
		lower = val
	}
	if val, found := strings.CutSuffix(lower, "^"); found {
		lower = val
	}

	// 4. Hosts 尾部清理
	fields := strings.Fields(lower)
	if len(fields) > 0 {
		lower = fields[0]
	}

	// 5. 域名校验
	return validateDomain(lower)
}

func validateDomain(domain string) (string, string) {
	domain = strings.Trim(domain, "./")
	if domain == "" {
		return "", "Empty"
	}
	if domain == "localhost" || domain == "local" {
		return "", "Localhost"
	}

	// 压缩逻辑：防止顶级域名 (TLD) 被误加入
	if !strings.Contains(domain, ".") {
		return "", "TLD/Single Word"
	}

	if !validRulePattern.MatchString(domain) {
		return "", "Invalid Chars"
	}

	// 通配符不进行 IDNA
	if strings.Contains(domain, "*") {
		return domain, ""
	}

	// Punycode 转码
	puny, err := idna.ToASCII(domain)
	if err != nil {
		return "", "Punycode Error"
	}

	return puny, ""
}

// removeSubdomains: 核心压缩算法，通过反转排序法去除冗余子域名。
func removeSubdomains(domains []string) ([]string, int) {
	type item struct {
		orig string
		rev  string
	}

	items := make([]item, 0, len(domains))
	for _, d := range domains {
		// 翻转域名: example.com -> com.example
		parts := strings.Split(d, ".")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		items = append(items, item{orig: d, rev: strings.Join(parts, ".")})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].rev < items[j].rev
	})

	var result []string
	removedCount := 0

	if len(items) == 0 {
		return result, 0
	}

	prev := items[0]
	result = append(result, prev.orig)

	for i := 1; i < len(items); i++ {
		curr := items[i]

		// 检查 curr 是否是 prev 的子域名
		if strings.HasPrefix(curr.rev, prev.rev+".") {
			removedCount++
			continue
		}

		result = append(result, curr.orig)
		prev = curr
	}

	return result, removedCount
}

// -----------------------------------------------------------------------------
// 文件 IO 及辅助工具
// -----------------------------------------------------------------------------

func loadInvalidDomains(path string) map[string]struct{} {
	set := make(map[string]struct{})
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf(">>> [Info] 未找到 %s，跳过加载排除列表。\n", path)
		return set
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		line = strings.ToLower(line)
		line = strings.TrimPrefix(line, "||")
		line = strings.TrimSuffix(line, "^")

		if line != "" {
			set[line] = struct{}{}
		}
	}
	fmt.Printf(">>> [Init] 已加载 %d 条排除域名规则\n", len(set))
	return set
}

func printMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("    [System] Alloc = %v MiB | TotalAlloc = %v MiB | Sys = %v MiB | NumGC = %v\n",
		m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
}

func printHeader() {
	fmt.Println(`
=========================================================
      AdGuard Rules Compiler - Expert Edition
=========================================================`)
}

func fetchUpstreamList(url string) []string {
	var list []string
	fmt.Printf(">>> [Init] 获取上游配置: %s\n", url)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("!!! 获取配置失败: %v\n", err)
		return list
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "http") {
			list = append(list, line)
		}
	}
	return list
}

func writeResultFile(filename string, lines []string) {
	f, _ := os.Create(filename)
	defer f.Close()
	w := bufio.NewWriter(f)

	fmt.Fprintf(w, "! Title: AdGuard Home Optimized List\n")
	fmt.Fprintf(w, "! Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "! Total Count: %d\n!\n", len(lines))

	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	w.Flush()
	fmt.Printf(">>> [File] 结果已保存至: %s\n", filename)
}

func writeDebugFile(filename string, logs []DebugEntry) {
	if len(logs) == 0 {
		return
	}
	f, _ := os.Create(filename)
	defer f.Close()
	w := bufio.NewWriter(f)

	fmt.Fprintf(w, "# Debug Log\n# Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# Total Entries: %d\n\n", len(logs))

	sort.Slice(logs, func(i, j int) bool {
		if logs[i].Reason != logs[j].Reason {
			return logs[i].Reason < logs[j].Reason
		}
		return logs[i].Source < logs[j].Source
	})

	for _, l := range logs {
		fmt.Fprintf(w, "[%-15s] %s | Src: %s\n", l.Reason, l.Line, l.Source)
	}
	w.Flush()
	fmt.Printf(">>> [File] Debug日志已保存至: %s\n", filename)
}

func trimLong(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
