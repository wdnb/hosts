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

// StatsCollector is an independent module for collecting and computing statistics.
// It uses a builder-like pattern for adding entries and can be extended without invading business logic.
// This reduces coupling: main logic reports events, StatsCollector handles aggregation.
type StatsCollector struct {
	debugLog                   []DebugEntry
	discardedBySource          map[string]int
	discardedByReason          map[string]int
	discardedBySourceAndReason map[string]map[string]int // New: Per-source breakdown of reasons (e.g., invalid_domains per upstream)
	sourceContribution         map[string]int
	sourceAccepted             map[string]int // New: Accepted (valid) rules per source before optimization
	sourceTotal                map[string]int // New: Total raw lines processed per source (including empties/comments)
	sourceUnique               map[string]int // New: Unique contributions after deduping across all sources
	optimizationPruned         []DebugEntry
	totalRaw                   int
	totalDiscarded             int
	totalFinal                 int
	mu                         sync.Mutex
}

// NewStatsCollector creates a new instance of StatsCollector.
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		debugLog:                   make([]DebugEntry, 0),
		discardedBySource:          make(map[string]int),
		discardedByReason:          make(map[string]int),
		discardedBySourceAndReason: make(map[string]map[string]int),
		sourceContribution:         make(map[string]int),
		sourceAccepted:             make(map[string]int),
		sourceTotal:                make(map[string]int),
		sourceUnique:               make(map[string]int),
		optimizationPruned:         make([]DebugEntry, 0),
	}
}

// AddDebugEntry adds a debug entry for discarded or invalid rules.
// Limits size to prevent memory issues.
func (sc *StatsCollector) AddDebugEntry(source, line, reason string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if len(sc.debugLog) < 1000000 {
		sc.debugLog = append(sc.debugLog, DebugEntry{Source: source, Line: line, Reason: reason})
	}
	if reason != "optimization" {
		sc.discardedBySource[source]++
		sc.discardedByReason[reason]++
		sc.totalDiscarded++
		if _, ok := sc.discardedBySourceAndReason[source]; !ok {
			sc.discardedBySourceAndReason[source] = make(map[string]int)
		}
		sc.discardedBySourceAndReason[source][reason]++
	}
}

// AddProcessedLine increments total lines processed per source.
func (sc *StatsCollector) AddProcessedLine(source string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.sourceTotal[source]++
}

// AddAcceptedRule tracks valid rules per source before deduping/optimization.
func (sc *StatsCollector) AddAcceptedRule(source, rule string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.sourceAccepted[source]++
}

// AddContribution tracks contributions after deduping.
func (sc *StatsCollector) AddContribution(rule string, sources map[string]bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for src := range sources {
		sc.sourceContribution[src]++
	}
	if len(sources) == 1 {
		for src := range sources {
			sc.sourceUnique[src]++
		}
	}
	sc.totalFinal++
}

// AddOptimizationPruned adds pruned entries from optimization phase.
func (sc *StatsCollector) AddOptimizationPruned(entries []DebugEntry) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.optimizationPruned = append(sc.optimizationPruned, entries...)
}

// SetTotalRaw sets the total raw rules after initial collection.
func (sc *StatsCollector) SetTotalRaw(total int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.totalRaw = total
}

// WriteToDebugFile writes all statistics and logs to the debug file.
// Focuses on useful metrics for identifying "garbage" upstreams:
// - High discard rates (e.g., many invalid_domains suggest poor quality).
// - Low unique contributions (much overlap or redundancy).
// - Breakdown of discards per reason per source.
// Removed meaningless stats (e.g., overly granular logs if not needed; kept detailed logs sorted).
// Added discard percentage per source for quality assessment.
func (sc *StatsCollector) WriteToDebugFile(filename string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("!!! 写入 %s 失败: %v\n", filename, err)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "# Debug Log\n# Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# Total Raw Rules: %d | Total Discarded (non-opt): %d | Total Final: %d\n\n", sc.totalRaw, sc.totalDiscarded, sc.totalFinal)
	// Discarded by Reason (global)
	fmt.Fprintf(w, "# Discarded Statistics by Reason (excluding optimizations) - Total: %d\n", sc.totalDiscarded)
	var reasonList []struct {
		reason string
		cnt    int
	}
	for r, c := range sc.discardedByReason {
		reasonList = append(reasonList, struct {
			reason string
			cnt    int
		}{reason: r, cnt: c})
	}
	sort.Slice(reasonList, func(i, j int) bool { return reasonList[i].cnt > reasonList[j].cnt })
	for _, rl := range reasonList {
		fmt.Fprintf(w, "# %s: %d\n", rl.reason, rl.cnt)
	}
	fmt.Fprintln(w)
	// Discarded by Source and Reason (detailed per-source breakdown)
	fmt.Fprintln(w, "# Discarded Statistics by Upstream Source and Reason (excluding optimizations)")
	var sourceList []string
	for s := range sc.discardedBySourceAndReason {
		sourceList = append(sourceList, s)
	}
	sort.Strings(sourceList)
	for _, src := range sourceList {
		fmt.Fprintf(w, "# Source: %s\n", src)
		reasons := sc.discardedBySourceAndReason[src]
		var reasonSubList []struct {
			reason string
			cnt    int
		}
		for r, c := range reasons {
			reasonSubList = append(reasonSubList, struct {
				reason string
				cnt    int
			}{reason: r, cnt: c})
		}
		sort.Slice(reasonSubList, func(i, j int) bool { return reasonSubList[i].cnt > reasonSubList[j].cnt })
		for _, rsl := range reasonSubList {
			fmt.Fprintf(w, "#   %s: %d\n", rsl.reason, rsl.cnt)
		}
	}
	fmt.Fprintln(w)
	// Source Quality Metrics (to identify garbage upstreams)
	fmt.Fprintln(w, "# Source Quality Metrics (to identify low-quality/garbage upstreams)")
	var qualityList []struct {
		src             string
		total           int
		accepted        int
		discarded       int
		discardPct      float64
		contribution    int
		unique          int
		uniquePct       float64
		contributionPct float64
	}
	for src := range sc.sourceTotal {
		total := sc.sourceTotal[src]
		accepted := sc.sourceAccepted[src]
		discarded := sc.discardedBySource[src]
		discardPct := 0.0
		if total > 0 {
			discardPct = float64(discarded) / float64(total) * 100
		}
		contrib := sc.sourceContribution[src]
		unique := sc.sourceUnique[src]
		uniquePct := 0.0
		if contrib > 0 {
			uniquePct = float64(unique) / float64(contrib) * 100
		}
		contribPct := 0.0
		if sc.totalFinal > 0 {
			contribPct = float64(contrib) / float64(sc.totalFinal) * 100
		}
		qualityList = append(qualityList, struct {
			src             string
			total           int
			accepted        int
			discarded       int
			discardPct      float64
			contribution    int
			unique          int
			uniquePct       float64
			contributionPct float64
		}{src: src, total: total, accepted: accepted, discarded: discarded, discardPct: discardPct,
			contribution: contrib, unique: unique, uniquePct: uniquePct, contributionPct: contribPct})
	}
	sort.Slice(qualityList, func(i, j int) bool { return qualityList[i].discardPct > qualityList[j].discardPct }) // Sort by worst discard % first
	for _, ql := range qualityList {
		fmt.Fprintf(w, "# %s: Total=%d | Accepted=%d | Discarded=%d (%.2f%%) | Contribution=%d (%.2f%% of final) | Unique=%d (%.2f%% of contrib)\n",
			ql.src, ql.total, ql.accepted, ql.discarded, ql.discardPct, ql.contribution, ql.contributionPct, ql.unique, ql.uniquePct)
	}
	fmt.Fprintln(w)
	// Optimization Pruned Logs
	fmt.Fprintln(w, "# Optimization Pruned Entries")
	sort.Slice(sc.optimizationPruned, func(i, j int) bool {
		if sc.optimizationPruned[i].Reason != sc.optimizationPruned[j].Reason {
			return sc.optimizationPruned[i].Reason < sc.optimizationPruned[j].Reason
		}
		return sc.optimizationPruned[i].Line < sc.optimizationPruned[j].Line
	})
	for _, l := range sc.optimizationPruned {
		fmt.Fprintf(w, "[optimization] %s | Reason: %s\n", l.Line, l.Reason)
	}
	fmt.Fprintln(w)
	// Detailed Discard Logs (non-optimization)
	fmt.Fprintln(w, "# Detailed Discard Logs (excluding optimizations)")
	var discardLogs []DebugEntry
	for _, l := range sc.debugLog {
		if l.Reason != "optimization" {
			discardLogs = append(discardLogs, l)
		}
	}
	sort.Slice(discardLogs, func(i, j int) bool {
		if discardLogs[i].Reason != discardLogs[j].Reason {
			return discardLogs[i].Reason < discardLogs[j].Reason
		}
		return discardLogs[i].Source < discardLogs[j].Source
	})
	for _, l := range discardLogs {
		fmt.Fprintf(w, "[%-15s] %s | Src: %s\n", l.Reason, l.Line, l.Source)
	}
	w.Flush()
	fmt.Printf(">>> [File] Debug日志已保存至: %s\n", filename)
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
	// Initialize independent stats collector
	stats := NewStatsCollector()
	// Use concurrency for downloading to speed up collection from multiple sources.
	var (
		blackSources = make(map[string]map[string]bool)
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
			validBlack, invalid := downloadAndProcess(u, invalidSet, stats)
			l := path.Base(u)
			mu.Lock()
			for _, r := range validBlack {
				if _, ok := blackSources[r]; !ok {
					blackSources[r] = make(map[string]bool)
				}
				blackSources[r][l] = true
			}
			mu.Unlock()
			// Report invalid to stats collector
			for _, inv := range invalid {
				stats.AddDebugEntry(l, inv.Line, inv.Reason)
			}
		}(i, url)
	}
	wg.Wait()
	printMemUsage()
	totalRaw := len(blackSources)
	stats.SetTotalRaw(totalRaw)
	fmt.Printf(">>> [Phase 1 Done] 初筛后规则总数: %d | 耗时: %v\n", totalRaw, time.Since(start))
	// Optimize rules to reduce redundancy, improving performance in ad-blockers.
	fmt.Println(">>> [Phase 2] 执行高级规则优化 (通配符剪枝 & 子域名剔除)...")
	wildcardsBlack := make([]string, 0)
	exactsBlack := make([]string, 0)
	for r, sources := range blackSources {
		// Report contributions to stats
		stats.AddContribution(r, sources)
		if strings.Contains(r, "*") {
			wildcardsBlack = append(wildcardsBlack, r)
		} else {
			exactsBlack = append(exactsBlack, r)
		}
	}
	optStart := time.Now()
	// Track pruned entries for debugging optimization effectiveness.
	prunedLog := make([]DebugEntry, 0)
	// Prune exact domains covered by wildcards to minimize list size without losing coverage (AdGuard only).
	remainingExactsBlack, wildcardPrunedCount := wildcardPruning(exactsBlack, wildcardsBlack, &prunedLog)
	// Remove subdomains covered by parents to further compress the list efficiently (AdGuard only).
	optimizedExactsBlack, subdomainPrunedCount := removeSubdomains(remainingExactsBlack, &prunedLog)
	totalPruned := wildcardPrunedCount + subdomainPrunedCount
	fmt.Printf(" -> 优化算法总耗时: %v\n", time.Since(optStart))
	fmt.Printf(" -> 1. 通配符剪枝剔除: %d 条\n", wildcardPrunedCount)
	fmt.Printf(" -> 2. 子域名剔除: %d 条\n", subdomainPrunedCount)
	fmt.Printf(" -> 总优化剔除: %d 条 (最终 AdGuard 黑名单规则数: %d)\n", totalPruned, len(wildcardsBlack)+len(optimizedExactsBlack))
	// Report optimization pruned to stats
	stats.AddOptimizationPruned(prunedLog)
	// Generate output files for use in AdGuard and AdAway.
	fmt.Println(">>> [Phase 3] 生成文件...")
	// AdGuard: Use optimized list with wildcards.
	adguardRules := generateAdGuardRules(wildcardsBlack, optimizedExactsBlack)
	writeResultFile(OutputFile, adguardRules)
	// AdAway: Use all original exact domains (no pruning, as hosts files don't support wildcards or subdomain coverage).
	adawayHosts := generateAdAwayHosts(exactsBlack)
	writeHostsFile(HostsOutputFile, adawayHosts)
	// Save debug logs via stats collector
	stats.WriteToDebugFile(DebugFile)
	fmt.Println("---------------------------------------------------------")
	fmt.Printf(">>> 全部完成!\n")
	fmt.Printf(">>> 最终 AdGuard 规则数: %d\n", len(adguardRules))
	fmt.Printf(">>> 最终 AdAway hosts 条目数: %d\n", len(adawayHosts))
	fmt.Printf(">>> 总耗时: %v\n", time.Since(start))
	fmt.Println("---------------------------------------------------------")
}

// -----------------------------------------------------------------------------
// Export Logic Separation: AdGuard Rules Generation
// -----------------------------------------------------------------------------
// generateAdGuardRules generates rules in AdGuard Home format, which supports wildcards (e.g., "*.black" to block all .black TLD domains).
// This function abstracts the AdGuard-specific formatting, separating it from AdAway logic for better maintainability.
func generateAdGuardRules(wildcards, exacts []string) []string {
	blackList := make([]string, 0, len(wildcards)+len(exacts))
	blackList = append(blackList, wildcards...)
	blackList = append(blackList, exacts...)
	sort.Strings(blackList)
	for i := range blackList {
		blackList[i] = fmt.Sprintf("||%s^", blackList[i])
	}
	return blackList
}

// -----------------------------------------------------------------------------
// Export Logic Separation: AdAway Hosts Generation
// -----------------------------------------------------------------------------
// generateAdAwayHosts generates hosts entries for AdAway, which does not support wildcards or parent-domain subdomain blocking.
// Only valid exact domains are included to comply with hosts file limitations. No pruning is applied to maximize coverage.
// This function abstracts the AdAway-specific formatting, separating it from AdGuard logic for better maintainability.
func generateAdAwayHosts(exacts []string) []string {
	hostsLines := make([]string, 0, len(exacts))
	for _, e := range exacts {
		if isValidDNSDomain(e) {
			hostsLines = append(hostsLines, fmt.Sprintf("%s %s", BlockingIP, e))
		}
	}
	sort.Strings(hostsLines)
	return hostsLines
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
func downloadAndProcess(url string, invalidSet map[string]struct{}, stats *StatsCollector) (validBlack []string, invalid []DebugEntry) {
	l := path.Base(url)
	client := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		invalid = append(invalid, DebugEntry{Line: "Network", Reason: err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		invalid = append(invalid, DebugEntry{Line: "Status", Reason: fmt.Sprint(resp.StatusCode)})
		return
	}
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		stats.AddProcessedLine(l) // Track total lines
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		clean, isWhite, reason := normalizeLine(line)
		if clean == "" {
			if len(line) > 5 {
				invalid = append(invalid, DebugEntry{Line: trimLong(line), Reason: reason})
			}
			continue
		}
		// Exclude invalid domains to protect against known malicious or irrelevant entries.
		if _, exists := invalidSet[clean]; exists {
			invalid = append(invalid, DebugEntry{Line: clean, Reason: "invalid_domains"})
			continue
		}
		if isWhite {
			invalid = append(invalid, DebugEntry{Line: clean, Reason: "discarded whitelist (potential malicious upstream)"})
			continue
		}
		validBlack = append(validBlack, clean)
		stats.AddAcceptedRule(l, clean) // Track accepted
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
// Supports wildcards like "*.black" for AdGuard compatibility.
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
// This function is used for AdGuard output.
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
// This function is used for AdAway output.
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

// Trims long strings to keep logs readable.
func trimLong(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
