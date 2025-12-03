package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path"
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
// Constants define fixed values used throughout the program to ensure consistency and ease of maintenance.
const (
	OutputFile         = "adblock_lite.txt"
	HostsOutputFile    = "adaway_hosts.txt" // Supports AdAway format for compatibility with hosts-based blockers.
	DebugFile          = "adblock_debug.txt"
	InvalidDomainsFile = "invalid_domains.txt" // Local file listing domains to exclude for security reasons.
	UserAgent          = "AdGuard-Compiler/4.0 (Go 1.23; Advanced Pruning)"
	MaxGoroutines      = 16 // Limits concurrency to prevent overwhelming system resources.
	UpstreamListSource = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"
	BlockingIP         = "0.0.0.0" // Uses a null IP for blocking in hosts files to efficiently prevent DNS resolution.
)

// Pattern ensures rules only contain safe characters to avoid injection or parsing errors.
var validRulePattern = regexp.MustCompile(`^[a-z0-9.\-_*]+$`)

// -----------------------------------------------------------------------------
// 类型定义
// -----------------------------------------------------------------------------
// DebugEntry captures details of discarded rules to aid in auditing and debugging potential issues.
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
	// Load invalid domains early to filter out known problematic entries during processing.
	invalidSet := loadInvalidDomains(InvalidDomainsFile)
	// Fetch upstream URLs to source rules from reliable, community-maintained lists.
	urls := fetchUpstreamList(UpstreamListSource)
	if len(urls) == 0 {
		fmt.Println("!!! 未获取到上游源，退出")
		return
	}
	// Use concurrency for downloading to speed up collection from multiple sources.
	var (
		blackSources = make(map[string]map[string]bool)
		debugLog     = make([]DebugEntry, 0)
		mu           sync.Mutex
		wg           sync.WaitGroup
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
			// Print progress periodically to provide user feedback on long-running operations.
			if idx > 0 && idx%5 == 0 {
				fmt.Printf(" -> 下载进度: %d/%d (总耗时: %v)\n", idx, totalUrls, time.Since(start).Round(time.Second))
			}
			// Process each source, filtering invalid domains to maintain list integrity.
			validBlack, invalid := downloadAndProcess(u, invalidSet)
			l := path.Base(u)
			mu.Lock()
			for _, r := range validBlack {
				if _, ok := blackSources[r]; !ok {
					blackSources[r] = make(map[string]bool)
				}
				blackSources[r][l] = true
			}
			// Limit debug log size to prevent excessive memory use on large error sets.
			if len(debugLog) < 1000000 {
				debugLog = append(debugLog, invalid...)
			}
			mu.Unlock()
		}(i, url)
	}
	wg.Wait()
	printMemUsage()
	totalRaw := len(blackSources)
	fmt.Printf(">>> [Phase 1 Done] 初筛后规则总数: %d | 耗时: %v\n", totalRaw, time.Since(start))
	// Optimize rules to reduce redundancy, improving performance in ad-blockers.
	fmt.Println(">>> [Phase 2] 执行高级规则优化 (通配符剪枝 & 子域名剔除)...")
	wildcardsBlack := make([]string, 0)
	exactsBlack := make([]string, 0)
	for r := range blackSources {
		if strings.Contains(r, "*") {
			wildcardsBlack = append(wildcardsBlack, r)
		} else {
			exactsBlack = append(exactsBlack, r)
		}
	}
	optStart := time.Now()
	// Track pruned entries for debugging optimization effectiveness.
	prunedLog := make([]DebugEntry, 0)
	// Prune exact domains covered by wildcards to minimize list size without losing coverage.
	remainingExactsBlack, wildcardPrunedCount := wildcardPruning(exactsBlack, wildcardsBlack, &prunedLog)
	// Remove subdomains covered by parents to further compress the list efficiently.
	optimizedExactsBlack, subdomainPrunedCount := removeSubdomains(remainingExactsBlack, &prunedLog)
	totalPruned := wildcardPrunedCount + subdomainPrunedCount
	fmt.Printf(" -> 优化算法总耗时: %v\n", time.Since(optStart))
	fmt.Printf(" -> 1. 通配符剪枝剔除: %d 条\n", wildcardPrunedCount)
	fmt.Printf(" -> 2. 子域名剔除: %d 条\n", subdomainPrunedCount)
	fmt.Printf(" -> 总优化剔除: %d 条 (最终黑名单规则数: %d)\n", totalPruned, len(wildcardsBlack)+len(optimizedExactsBlack))
	// Generate output files for use in AdGuard and AdAway.
	fmt.Println(">>> [Phase 3] 生成文件...")
	blackList := make([]string, 0, len(wildcardsBlack)+len(optimizedExactsBlack))
	blackList = append(blackList, wildcardsBlack...)
	blackList = append(blackList, optimizedExactsBlack...)
	sort.Strings(blackList)
	for i := range blackList {
		blackList[i] = fmt.Sprintf("||%s^", blackList[i])
	}
	// Append optimization logs to main debug for comprehensive tracking.
	debugLog = append(debugLog, prunedLog...)
	// Compute discarded statistics excluding optimizations
	discardedBySource := make(map[string]int)
	for _, entry := range debugLog {
		if entry.Source != "optimization" {
			discardedBySource[entry.Source]++
		}
	}
	// Compute rule contribution statistics
	finalBlack := make(map[string]struct{})
	for _, r := range wildcardsBlack {
		finalBlack[r] = struct{}{}
	}
	for _, r := range optimizedExactsBlack {
		finalBlack[r] = struct{}{}
	}
	sourceContribution := make(map[string]int)
	for rule := range finalBlack {
		if sources, ok := blackSources[rule]; ok {
			for src := range sources {
				sourceContribution[src]++
			}
		}
	}
	// Write AdGuard-compatible file for broad ad-blocker support.
	writeResultFile(OutputFile, blackList)
	// Generate hosts file only with valid exact domains for DNS-level blocking.
	hostsLines := make([]string, 0, len(optimizedExactsBlack))
	for _, e := range optimizedExactsBlack {
		if isValidDNSDomain(e) {
			hostsLines = append(hostsLines, fmt.Sprintf("%s %s", BlockingIP, e))
		}
	}
	sort.Strings(hostsLines)
	writeHostsFile(HostsOutputFile, hostsLines)
	// Save debug logs to facilitate review of discarded rules.
	writeDebugFile(DebugFile, debugLog, discardedBySource, sourceContribution, len(finalBlack))
	fmt.Println("---------------------------------------------------------")
	fmt.Printf(">>> 全部完成!\n")
	fmt.Printf(">>> 最终 AdGuard 规则数: %d\n", len(blackList))
	fmt.Printf(">>> 最终 AdAway hosts 条目数: %d\n", len(hostsLines))
	fmt.Printf(">>> 总耗时: %v\n", time.Since(start))
	fmt.Println("---------------------------------------------------------")
}

// -----------------------------------------------------------------------------
// 压缩算法 V2: 通配符剪枝
// -----------------------------------------------------------------------------
// Prunes exact domains to avoid duplication where wildcards provide equivalent coverage, reducing list bloat.
func wildcardPruning(exacts []string, wildcards []string, prunedLog *[]DebugEntry) ([]string, int) {
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
				delete(exactMap, exact)
				removedCount++
				*prunedLog = append(*prunedLog, DebugEntry{Source: "optimization", Line: exact, Reason: "pruned by wildcard black: " + pattern})
				break
			}
		}
	}
	remainingExacts := make([]string, 0, len(exactMap))
	for e := range exactMap {
		remainingExacts = append(remainingExacts, e)
	}
	return remainingExacts, removedCount
}

// Checks coverage to ensure pruning doesn't weaken blocking effectiveness.
func isCoveredByWildcard(exact string, pattern string) bool {
	parts := strings.Split(pattern, "*")
	idx := 0
	if parts[0] != "" {
		if !strings.HasPrefix(exact, parts[0]) {
			return false
		}
		idx = len(parts[0])
	}
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		foundIdx := strings.Index(exact[idx:], part)
		if foundIdx == -1 {
			return false
		}
		idx += foundIdx + len(part)
	}
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

// Removes subdomains via reversed sorting to efficiently detect and eliminate redundancies in hierarchical domains.
func removeSubdomains(domains []string, prunedLog *[]DebugEntry) ([]string, int) {
	type item struct {
		orig string
		rev  string
	}
	items := make([]item, 0, len(domains))
	for _, d := range domains {
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
		if strings.HasPrefix(curr.rev, prev.rev+".") {
			removedCount++
			*prunedLog = append(*prunedLog, DebugEntry{Source: "optimization", Line: curr.orig, Reason: "subdomain pruned by parent: " + prev.orig})
			continue
		}
		result = append(result, curr.orig)
		prev = curr
	}
	return result, removedCount
}

// -----------------------------------------------------------------------------
// 核心逻辑 (清洗与校验)
// -----------------------------------------------------------------------------
func downloadAndProcess(url string, invalidSet map[string]struct{}) (validBlack []string, invalid []DebugEntry) {
	l := path.Base(url)
	client := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		invalid = append(invalid, DebugEntry{Source: l, Line: "Network", Reason: err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		invalid = append(invalid, DebugEntry{Source: l, Line: "Status", Reason: fmt.Sprint(resp.StatusCode)})
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
		clean, isWhite, reason := normalizeLine(line)
		if clean == "" {
			if len(line) > 5 {
				invalid = append(invalid, DebugEntry{Source: l, Line: trimLong(line), Reason: reason})
			}
			continue
		}
		// Exclude invalid domains to protect against known malicious or irrelevant entries.
		if _, exists := invalidSet[clean]; exists {
			invalid = append(invalid, DebugEntry{Source: l, Line: clean, Reason: "invalid_domains"})
			continue
		}
		if isWhite {
			invalid = append(invalid, DebugEntry{Source: l, Line: clean, Reason: "discarded whitelist (potential malicious upstream)"})
			continue
		}
		validBlack = append(validBlack, clean)
	}
	return
}

// Normalizes lines to standardize rule format, ensuring consistency across diverse upstream sources.
func normalizeLine(line string) (string, bool, string) {
	lower := strings.ToLower(line)
	isWhite := false
	if before, _, found := strings.Cut(lower, "$"); found {
		lower = strings.TrimSpace(before)
	}
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
	if val, found := strings.CutPrefix(lower, "@@||"); found {
		isWhite = true
		lower = val
	} else if val, found := strings.CutPrefix(lower, "||"); found {
		lower = val
	}
	if val, found := strings.CutSuffix(lower, "^"); found {
		lower = val
	}
	fields := strings.Fields(lower)
	if len(fields) > 0 {
		lower = fields[0]
	}
	clean, reason := validateDomain(lower)
	return clean, isWhite, reason
}

// Validates domains to enforce DNS compliance and prevent invalid or harmful rules.
func validateDomain(domain string) (string, string) {
	domain = strings.Trim(domain, "./")
	if domain == "" {
		return "", "Empty"
	}
	if domain == "localhost" || domain == "local" {
		return "", "Localhost"
	}
	if !strings.Contains(domain, ".") {
		return "", "TLD/Single Word"
	}
	if !validRulePattern.MatchString(domain) {
		return "", "Invalid Chars"
	}
	if strings.Contains(domain, "*") {
		return domain, ""
	}
	puny, err := idna.ToASCII(domain)
	if err != nil {
		return "", "Punycode Error"
	}
	return puny, ""
}

// Ensures domain validity for hosts files to comply with DNS resolution standards.
func isValidDNSDomain(domain string) bool {
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	parts := strings.Split(domain, ".")
	for _, p := range parts {
		if len(p) == 0 || len(p) > 63 {
			return false
		}
		if strings.HasPrefix(p, "-") || strings.HasSuffix(p, "-") {
			return false
		}
		for _, c := range p {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// 文件 IO 及辅助工具
// -----------------------------------------------------------------------------
// Loads invalid domains to preemptively filter out unwanted entries.
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

// Monitors memory to detect and mitigate potential leaks during processing.
func printMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf(" [System] Alloc = %v MiB | TotalAlloc = %v MiB | Sys = %v MiB | NumGC = %v\n",
		m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
}

// Displays header for user orientation at program start.
func printHeader() {
	fmt.Println(`
=========================================================
      AdGuard Rules Compiler - Expert Edition (with AdAway Export)
=========================================================`)
}

// Fetches upstream list to dynamically source rules without hardcoding.
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

// Writes results with metadata for traceability in ad-blocker usage.
func writeResultFile(filename string, lines []string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("!!! 写入 %s 失败: %v\n", filename, err)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "! Title: AdGuard Home Optimized List\n")
	fmt.Fprintf(w, "! Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "! Total Count: %d\n!\n", len(lines))
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	w.Flush()
	fmt.Printf(">>> [File] AdGuard 结果已保存至: %s\n", filename)
}

// Writes hosts file for alternative blocking methods.
func writeHostsFile(filename string, lines []string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("!!! 写入 %s 失败: %v\n", filename, err)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "# Title: AdAway Hosts File (from AdGuard Optimized List)\n")
	fmt.Fprintf(w, "# Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# Total Count: %d\n#\n", len(lines))
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	w.Flush()
	fmt.Printf(">>> [File] AdAway hosts 已保存至: %s\n", filename)
}

// Sorts and writes debug logs for organized review.
func writeDebugFile(filename string, logs []DebugEntry, discardedBySource map[string]int, sourceContribution map[string]int, totalFinal int) {
	if len(logs) == 0 {
		return
	}
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("!!! 写入 %s 失败: %v\n", filename, err)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "# Debug Log\n# Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# Total Entries: %d\n\n", len(logs))

	// Write discarded statistics
	fmt.Fprintln(w, "# Discarded Statistics by Upstream Source (excluding optimizations)")
	type srcCount struct {
		src string
		cnt int
	}
	var discardedList []srcCount
	for s, c := range discardedBySource {
		discardedList = append(discardedList, srcCount{src: s, cnt: c})
	}
	sort.Slice(discardedList, func(i, j int) bool {
		return discardedList[i].cnt > discardedList[j].cnt
	})
	for _, sc := range discardedList {
		fmt.Fprintf(w, "# %s: %d\n", sc.src, sc.cnt)
	}
	fmt.Fprintln(w)

	// Write contribution statistics
	fmt.Fprintln(w, "# Rule Contribution by Upstream Source")
	var contribList []struct {
		src string
		cnt int
		pct float64
	}
	for s, c := range sourceContribution {
		pct := 0.0
		if totalFinal > 0 {
			pct = float64(c) / float64(totalFinal) * 100
		}
		contribList = append(contribList, struct {
			src string
			cnt int
			pct float64
		}{src: s, cnt: c, pct: pct})
	}
	sort.Slice(contribList, func(i, j int) bool {
		return contribList[i].cnt > contribList[j].cnt
	})
	for _, sc := range contribList {
		fmt.Fprintf(w, "# %s: %d (%.2f%%)\n", sc.src, sc.cnt, sc.pct)
	}
	fmt.Fprintln(w, "\n# Detailed Logs")

	// Write sorted detailed logs
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

// Trims long strings to keep logs readable.
func trimLong(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
