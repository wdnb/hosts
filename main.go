package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/time/rate"
)

// -----------------------------------------------------------------------------
// 配置与常量
// -----------------------------------------------------------------------------
// Why: Group all constants at the top for easy configuration changes; avoids scattering values that could lead to inconsistencies.
const (
	OutputFile         = "adblock_lite.txt"
	HostsOutputFile    = "adaway_hosts.txt"
	DebugFile          = "adblock_debug.txt"
	InvalidDomainsFile = "invalid_domains.txt"
	UserAgent          = "AdGuard-Compiler/4.0 (Go 1.23; Advanced Pruning)"
	MaxGoroutines      = 16
	UpstreamListSource = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"
	BlockingIP         = "0.0.0.0"

	DNSTimeout              = 1000 * time.Millisecond
	TestDomain              = "t.cn"
	MaxDNSConcurrency       = 500
	QPSPerServer            = 200
	BurstPerServer          = 200
	DebugInvalidSourcesFile = "debug_invalid_sources.txt"
)

// Why: Define modes as constants to avoid magic numbers in function parameters; improves readability when switching behaviors.
const (
	ModeNormal int = iota
	ModeInvalidGen
)

// Why: Precompile regex for performance; it's used multiple times in validation, so compiling once reduces overhead.
var validRulePattern = regexp.MustCompile(`^[a-z0-9.\-_*]+$`)

// Why: Separate DNS lists by region to allow randomized selection between local (faster for some users) and global servers, improving resolution reliability.
var chinaDNS = []string{
	"223.5.5.5:53", "223.6.6.6:53", "114.114.114.114:53", "114.114.115.115:53",
	"180.76.76.76:53", "119.29.29.29:53", "182.254.116.116:53",
}

var globalDNS = []string{
	"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53",
	"9.9.9.9:53", "149.112.112.112:53", "208.67.222.222:53", "208.67.220.220:53",
	"94.140.14.140:53", "94.140.14.141:53", // AdGuard DNS Unfiltered
	"208.67.222.2:53", "208.67.220.2:53", // Cisco OpenDNS Sandbox (unfiltered)
	"76.76.2.0:53", "76.76.10.0:53", // ControlD Unfiltered
	"185.222.222.222:53", "45.11.45.11:53", // DNS.SB
	"54.174.40.213:53", "52.3.100.184:53", // DNSWatchGO (malware prevention, closest to unfiltered)
	"216.146.35.35:53", "216.146.36.36:53", // Dyn DNS
	"80.80.80.80:53", "80.80.81.81:53", // Freenom World
	"74.82.42.42:53", // Hurricane Electric
}

// -----------------------------------------------------------------------------
// 类型定义
// -----------------------------------------------------------------------------
// Why: Use a struct for debug entries to keep related data together; easier to extend if more fields are needed later.
type DebugEntry struct {
	Source string
	Line   string
	Reason string
}

// -----------------------------------------------------------------------------
// 主程序
// -----------------------------------------------------------------------------
// Why: Main serves as the entry point; it orchestrates phases sequentially to ensure dependencies (e.g., invalid list before rule processing) are respected.
func main() {
	// Why: Parse flags early to allow conditional behavior without runtime checks everywhere; keeps the flow linear.
	genInvalid := flag.Bool("gen-invalid", false, "是否生成 invalid_domains.txt (默认 false)")
	flag.Parse()

	start := time.Now()
	printHeader()

	urls := fetchUpstreamList(UpstreamListSource)
	if len(urls) == 0 {
		fmt.Println("!!! 未获取到上游源，退出")
		return
	}

	// Why: Check the flag here to optionally run the pre-phase; avoids unnecessary DNS work in normal runs, saving time.
	if *genInvalid {
		generateInvalidDomains(urls, start)
	} else {
		fmt.Println(">>> [Info] 跳过 invalid_domains.txt 生成 (使用 -gen-invalid=true 以启用)")
	}

	// Why: Load invalid set after potential generation; ensures the latest exclusions are used if generated, or falls back gracefully if not.
	invalidSet := loadInvalidDomains(InvalidDomainsFile)

	var blackRaw = make(map[string]struct{})
	var whiteRaw = make(map[string]struct{})
	var debugLog = make([]DebugEntry, 0)

	fmt.Printf(">>> [Phase 1] 开始并发下载 %d 个源...\n", len(urls))
	// Why: Use concurrent download for efficiency; processes multiple URLs in parallel but limits goroutines to prevent overwhelming the system.
	concurrentDownload(urls, MaxGoroutines, start, func(u string) interface{} {
		vb, vw, inv := downloadRules(u, ModeNormal, invalidSet)
		return struct {
			black, white []string
			invalid      []DebugEntry
		}{vb, vw, inv}
	}, func(res interface{}, mu *sync.Mutex) {
		r := res.(struct {
			black, white []string
			invalid      []DebugEntry
		})
		mu.Lock()
		for _, b := range r.black {
			blackRaw[b] = struct{}{}
		}
		for _, w := range r.white {
			whiteRaw[w] = struct{}{}
		}
		// Why: Cap debug log size to prevent memory exhaustion; prioritizes early errors while avoiding unbounded growth.
		if len(debugLog) < 1000000 {
			debugLog = append(debugLog, r.invalid...)
		}
		mu.Unlock()
	})

	printMemUsage()
	totalRaw := len(blackRaw) + len(whiteRaw)
	fmt.Printf(">>> [Phase 1 Done] 初筛后规则总数: %d | 耗时: %v\n", totalRaw, time.Since(start))

	fmt.Println(">>> [Phase 2] 执行高级规则优化 (通配符剪枝 & 子域名剔除)...")
	wildcardsBlack := make([]string, 0)
	exactsBlack := make([]string, 0)
	// Why: Separate wildcards and exacts early; allows targeted optimizations, as wildcards need different handling to avoid over-pruning.
	for r := range blackRaw {
		if strings.Contains(r, "*") {
			wildcardsBlack = append(wildcardsBlack, r)
		} else {
			exactsBlack = append(exactsBlack, r)
		}
	}
	wildWhites := make([]string, 0)
	for w := range whiteRaw {
		if strings.Contains(w, "*") {
			wildWhites = append(wildWhites, w)
		}
	}
	optStart := time.Now()
	prunedLog := make([]DebugEntry, 0)
	remainingExactsBlack, wildcardPrunedCount := wildcardPruning(exactsBlack, wildcardsBlack, &prunedLog)
	optimizedExactsBlack, subdomainPrunedCount := removeSubdomains(remainingExactsBlack, &prunedLog)
	totalPruned := wildcardPrunedCount + subdomainPrunedCount
	fmt.Printf(" -> 优化算法总耗时: %v\n", time.Since(optStart))
	fmt.Printf(" -> 1. 通配符剪枝剔除: %d 条\n", wildcardPrunedCount)
	fmt.Printf(" -> 2. 子域名剔除: %d 条\n", subdomainPrunedCount)
	fmt.Printf(" -> 总优化剔除: %d 条 (最终黑名单规则数: %d)\n", totalPruned, len(wildcardsBlack)+len(optimizedExactsBlack))

	fmt.Println(">>> [Phase 3] 生成文件...")
	blackList := make([]string, 0, len(wildcardsBlack)+len(optimizedExactsBlack))
	for _, w := range wildcardsBlack {
		if _, ok := whiteRaw[w]; !ok {
			blackList = append(blackList, fmt.Sprintf("||%s^", w))
		} else {
			prunedLog = append(prunedLog, DebugEntry{"optimization", w, "excluded by exact whitelist"})
		}
	}
	for _, e := range optimizedExactsBlack {
		if _, ok := whiteRaw[e]; ok {
			prunedLog = append(prunedLog, DebugEntry{"optimization", e, "excluded by exact whitelist"})
			continue
		}
		covered := false
		// Why: Check wildcard whites separately; ensures exact blacks aren't accidentally whitelisted by broader patterns, maintaining precision.
		for _, ww := range wildWhites {
			if isCoveredByWildcard(e, ww) {
				covered = true
				prunedLog = append(prunedLog, DebugEntry{"optimization", e, "excluded by wildcard whitelist: " + ww})
				break
			}
		}
		if covered {
			continue
		}
		blackList = append(blackList, fmt.Sprintf("||%s^", e))
	}
	// Why: Sort lists for deterministic output; useful for diffing files or ensuring consistent behavior across runs.
	sort.Strings(blackList)
	whiteList := make([]string, 0, len(whiteRaw))
	for w := range whiteRaw {
		whiteList = append(whiteList, w)
	}
	sort.Strings(whiteList)
	finalList := append(blackList, make([]string, 0, len(whiteList))...)
	for _, w := range whiteList {
		finalList = append(finalList, fmt.Sprintf("@@||%s^", w))
	}
	debugLog = append(debugLog, prunedLog...)
	writeResultFile(OutputFile, finalList)
	hostsLines := make([]string, 0, len(optimizedExactsBlack))
	for _, e := range optimizedExactsBlack {
		if _, ok := whiteRaw[e]; !ok {
			covered := false
			for _, ww := range wildWhites {
				if isCoveredByWildcard(e, ww) {
					covered = true
					break
				}
			}
			if !covered && isValidDNSDomain(e) {
				hostsLines = append(hostsLines, fmt.Sprintf("%s %s", BlockingIP, e))
			}
		}
	}
	sort.Strings(hostsLines)
	writeHostsFile(HostsOutputFile, hostsLines)
	writeDebugFile(DebugFile, debugLog)
	fmt.Println("---------------------------------------------------------")
	fmt.Printf(">>> 全部完成!\n")
	fmt.Printf(">>> 最终 AdGuard 规则数: %d\n", len(finalList))
	fmt.Printf(">>> 最终 AdAway hosts 条目数: %d\n", len(hostsLines))
	fmt.Printf(">>> 总耗时: %v\n", time.Since(start))
	fmt.Println("---------------------------------------------------------")
}

// -----------------------------------------------------------------------------
// invalid_domains 生成
// -----------------------------------------------------------------------------
// Why: Isolate invalid generation in a function; allows conditional execution without cluttering main, and reuses components like concurrentDownload.
func generateInvalidDomains(urls []string, overallStart time.Time) {
	// Why: Seed rand here for reproducibility in tests; ensures consistent random DNS selection across runs if needed.
	rand.Seed(time.Now().UnixNano())
	genStart := time.Now()
	fmt.Println(">>> [Pre-Phase] 生成 invalid_domains.txt (DNS 无效检测)...")

	availableChina := filterAvailableDNS(chinaDNS)
	availableGlobal := filterAvailableDNS(globalDNS)
	// Why: Early exit if no DNS available; prevents wasting time on downloads if validation can't proceed.
	if len(availableChina) == 0 && len(availableGlobal) == 0 {
		fmt.Println("!!! [Pre-Phase] 无可用 DNS 服务器，跳过 invalid_domains 生成")
		return
	}
	fmt.Printf(">>> [Pre-Phase DNS] 可用 DNS - China: %d, Global: %d\n", len(availableChina), len(availableGlobal))

	// Why: Create limiters per server; prevents rate-limiting issues by controlling queries individually.
	limiters := make(map[string]*rate.Limiter)
	for _, s := range append(availableChina, availableGlobal...) {
		limiters[s] = rate.NewLimiter(rate.Limit(QPSPerServer), BurstPerServer)
	}

	ruleSources := make(map[string]map[string]struct{})
	fmt.Printf(">>> [Pre-Phase Download] 并发下载 %d 个源 (复用上游)...\n", len(urls))
	// Why: Reuse concurrentDownload; matches the pattern in main for consistency, even though data needs differ slightly.
	concurrentDownload(urls, MaxGoroutines, overallStart, func(u string) interface{} {
		rules, _, _ := downloadRules(u, ModeInvalidGen, nil)
		// Why: Return struct with url; passes per-URL data to aggregator without relying on closures, avoiding scope issues.
		return struct {
			rules []string
			url   string
		}{rules, u}
	}, func(res interface{}, mu *sync.Mutex) {
		r := res.(struct {
			rules []string
			url   string
		})
		mu.Lock()
		for _, rule := range r.rules {
			if _, ok := ruleSources[rule]; !ok {
				ruleSources[rule] = make(map[string]struct{})
			}
			ruleSources[rule][r.url] = struct{}{}
		}
		mu.Unlock()
	})

	totalRaw := len(ruleSources)
	fmt.Printf(">>> [Pre-Phase Download] 完成。去重后规则数: %d\n", totalRaw)

	checkQueue := make([]string, 0, totalRaw)
	for r := range ruleSources {
		checkQueue = append(checkQueue, r)
	}

	fmt.Printf(">>> [Pre-Phase DNS Check] 开始验证 (并发: %d, 超时: %v, QPS/服务器: %d)...\n", MaxDNSConcurrency, DNSTimeout, QPSPerServer)
	invalidDomains, invalidSources := checkDomainsForInvalid(checkQueue, availableChina, availableGlobal, limiters, ruleSources)

	fmt.Printf(">>> [Pre-Phase Output] 无效域名: %d (有效: %d)\n", len(invalidDomains), totalRaw-len(invalidDomains))
	// Why: Sort before writing; ensures output is predictable and easier to compare across generations.
	sort.Strings(invalidDomains)
	if err := writeInvalidToFile(InvalidDomainsFile, invalidDomains); err != nil {
		fmt.Printf("!!! [Pre-Phase] 写入 invalid_domains.txt 失败: %v\n", err)
		return
	}
	if err := writeDebugInvalidSources(DebugInvalidSourcesFile, invalidSources); err != nil {
		fmt.Printf("!!! [Pre-Phase] 写入 debug_invalid_sources.txt 失败: %v\n", err)
	}
	fmt.Printf(">>> [Pre-Phase Done] 完成，耗时: %v\n", time.Since(genStart))
}

// -----------------------------------------------------------------------------
// 抽象并发下载
// -----------------------------------------------------------------------------
// Why: Abstract concurrency into a function; allows reuse across phases with different processors/aggregators, reducing duplication.
func concurrentDownload(urls []string, maxConc int, start time.Time, processor func(string) interface{}, aggregator func(interface{}, *sync.Mutex)) {
	var wg sync.WaitGroup
	// Why: Use semaphore to limit concurrency; prevents too many goroutines from overwhelming network or CPU.
	sem := make(chan struct{}, maxConc)
	mu := sync.Mutex{}

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// Why: Print progress every 5 to balance feedback without flooding output; helps monitor long-running tasks.
			if idx > 0 && idx%5 == 0 {
				fmt.Printf(" -> 下载进度: %d/%d (总耗时: %v)\n", idx, len(urls), time.Since(start).Round(time.Second))
			}
			result := processor(url)
			aggregator(result, &mu)
		}(i, u)
	}
	wg.Wait()
}

// -----------------------------------------------------------------------------
// 合并下载逻辑
// -----------------------------------------------------------------------------
// Why: Merge download logic into one function with modes; reduces code duplication between normal and invalid phases while handling differences conditionally.
func downloadRules(url string, mode int, invalidSet map[string]struct{}) (black []string, white []string, invalids []DebugEntry) {
	resp, err := fetchResponse(url)
	if err != nil {
		// Why: Only log in normal mode; invalid gen doesn't need debug for network issues to keep output focused.
		if mode == ModeNormal {
			invalids = append(invalids, DebugEntry{url, "Network", err.Error()})
		}
		return
	}
	if resp.StatusCode != 200 {
		if mode == ModeNormal {
			invalids = append(invalids, DebugEntry{url, "Status", fmt.Sprint(resp.StatusCode)})
		}
		resp.Body.Close()
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	// Why: Buffer large to handle big files efficiently; prevents frequent reallocations during scanning.
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	// Why: Use base path for source; shortens debug entries without losing context.
	source := path.Base(url)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		clean, isWhite, reason := normalizeLine(line)
		if clean == "" {
			// Why: Skip short lines in logging; reduces noise in debug output.
			if mode == ModeNormal && len(line) > 5 {
				invalids = append(invalids, DebugEntry{source, trimLong(line), reason})
			}
			continue
		}
		if mode == ModeNormal {
			// Why: Filter invalids only in normal mode; invalid gen doesn't use the set to avoid circular logic.
			if _, exists := invalidSet[clean]; exists {
				invalids = append(invalids, DebugEntry{source, clean, "invalid_domains"})
				continue
			}
		}
		if isWhite {
			if mode == ModeNormal {
				white = append(white, clean)
			}
		} else {
			if mode == ModeNormal {
				black = append(black, clean)
			} else if !strings.Contains(clean, "*") {
				// Why: Format as AdGuard in invalid mode; standardizes for DNS checks without wildcards.
				black = append(black, fmt.Sprintf("||%s^", clean))
			}
		}
	}
	return
}

// -----------------------------------------------------------------------------
// HTTP 抽象
// -----------------------------------------------------------------------------
// Why: Centralize HTTP requests; ensures consistent timeouts and headers, easier to tweak globally.
func fetchResponse(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	return client.Do(req)
}

// -----------------------------------------------------------------------------
// 上游列表获取
// -----------------------------------------------------------------------------
// Why: Reuse fetchResponse; keeps consistency with other downloads, avoids duplicating HTTP logic.
func fetchUpstreamList(url string) []string {
	var list []string
	fmt.Printf(">>> [Init] 获取上游配置: %s\n", url)
	resp, err := fetchResponse(url)
	if err != nil {
		fmt.Printf("!!! 获取配置失败: %v\n", err)
		return list
	}
	if resp.StatusCode != 200 {
		fmt.Printf("!!! 获取配置失败: status %d\n", resp.StatusCode)
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

// -----------------------------------------------------------------------------
// DNS 相关
// -----------------------------------------------------------------------------
// Why: Filter available DNS upfront; skips unreliable servers to improve overall success rate.
func filterAvailableDNS(servers []string) []string {
	var available []string
	for _, server := range servers {
		if checkDNSServer(server) {
			available = append(available, server)
		}
	}
	return available
}

// Why: Use a test domain for check; verifies connectivity without assuming user domains are valid.
func checkDNSServer(server string) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: DNSTimeout}
			return d.DialContext(ctx, "udp", server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
	defer cancel()
	ips, err := resolver.LookupHost(ctx, TestDomain)
	return err == nil && len(ips) > 0
}

// Why: Use worker pool for DNS checks; handles high volume concurrently while capping workers for resource control.
func checkDomainsForInvalid(rules []string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter, ruleSources map[string]map[string]struct{}) ([]string, map[string][]string) {
	var invalidDomains []string
	var invalidSources = make(map[string][]string)
	var mu sync.Mutex

	jobs := make(chan string, len(rules))
	var wg sync.WaitGroup

	var processedCount int32
	total := int32(len(rules))

	for i := 0; i < MaxDNSConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rule := range jobs {
				domain := extractDomain(rule)

				// Why: Skip invalid formats early; reduces unnecessary DNS queries for non-domain rules.
				if domain == "" || strings.Contains(domain, "*") || !strings.Contains(domain, ".") {
					continue
				}

				if !isDomainAlive(domain, availableChina, availableGlobal, limiters) {
					mu.Lock()
					invalidDomains = append(invalidDomains, domain)
					sources := make([]string, 0, len(ruleSources[rule]))
					for u := range ruleSources[rule] {
						sources = append(sources, u)
					}
					// Why: Sort sources for consistent debug output; easier to compare logs.
					sort.Strings(sources)
					invalidSources[domain] = sources
					mu.Unlock()
				}

				// Why: Update progress atomically; safe for concurrent access without locks on every increment.
				current := atomic.AddInt32(&processedCount, 1)
				if current%5000 == 0 {
					fmt.Printf("\r--> 进度: %d / %d (%.1f%%)", current, total, float64(current)/float64(total)*100)
				}
			}
		}()
	}

	for _, r := range rules {
		jobs <- r
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
	return invalidDomains, invalidSources
}

// Why: Extract domain from formatted rule; standardizes input for DNS checks.
func extractDomain(rule string) string {
	if strings.HasPrefix(rule, "||") && strings.HasSuffix(rule, "^") {
		return rule[2 : len(rule)-1]
	}
	return ""
}

// Why: Randomize list order; balances load and improves success by trying regional/global alternately.
func isDomainAlive(domain string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter) bool {
	lists := [][]string{availableChina, availableGlobal}
	initialIdx := rand.Intn(2)
	otherIdx := 1 - initialIdx

	if tryDNSList(lists[initialIdx], domain, limiters) {
		return true
	}

	return tryDNSList(lists[otherIdx], domain, limiters)
}

// Why: Random server selection; distributes queries evenly to avoid overloading one server.
func tryDNSList(servers []string, domain string, limiters map[string]*rate.Limiter) bool {
	if len(servers) == 0 {
		return false
	}

	idx := rand.Intn(len(servers))
	server := servers[idx]

	limiter := limiters[server]
	if err := limiter.Wait(context.Background()); err != nil {
		return false
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: DNSTimeout}
			return d.DialContext(ctx, "udp", server)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, domain)
	return err == nil && len(ips) > 0
}

// -----------------------------------------------------------------------------
// 优化算法
// -----------------------------------------------------------------------------
// Why: Use map for pruning; allows O(1) deletes, efficient for large lists.
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
				*prunedLog = append(*prunedLog, DebugEntry{"optimization", exact, "pruned by wildcard black: " + pattern})
				// Why: Break early; stops checking once matched, saves time on large wildcard lists.
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

// Why: Split pattern for flexible matching; handles various wildcard positions without regex for speed.
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

// Why: Reverse domains for sorting; enables prefix check to detect subdomains efficiently in O(n log n).
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
			*prunedLog = append(*prunedLog, DebugEntry{"optimization", curr.orig, "subdomain pruned by parent: " + prev.orig})
			continue
		}
		result = append(result, curr.orig)
		prev = curr
	}
	return result, removedCount
}

// -----------------------------------------------------------------------------
// 规则清洗
// -----------------------------------------------------------------------------
// Why: Normalize in loops; handles multiple prefixes iteratively to clean various formats without complex regex.
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

// Why: Trim and check basics first; quick fails reduce calls to expensive IDNA conversion.
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

// Why: Strict DNS checks; ensures hosts file compatibility, preventing invalid entries that could break resolvers.
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
// 文件 IO 及辅助
// -----------------------------------------------------------------------------
// Why: Skip comments and normalize; ensures clean set without extras that could falsely exclude valid rules.
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

// Why: Monitor memory; helps diagnose leaks or high usage during long runs.
func printMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf(" [System] Alloc = %v MiB | TotalAlloc = %v MiB | Sys = %v MiB | NumGC = %v\n",
		m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
}

// Why: Print header; provides visual separation and context at start.
func printHeader() {
	fmt.Println(`
=========================================================
      AdGuard Rules Compiler - Expert Edition (with AdAway Export)
=========================================================`)
}

// Why: Use buffered writer; efficient for large files, reduces I/O calls.
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

// Why: Sort logs; groups by reason then source for easier analysis in debug file.
func writeDebugFile(filename string, logs []DebugEntry) {
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

func writeInvalidToFile(filename string, domains []string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "! Title: Invalid Domains List (DNS Checked)")
	fmt.Fprintf(w, "! Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "! Count: %d\n", len(domains))
	fmt.Fprintln(w, "!")

	for _, domain := range domains {
		fmt.Fprintln(w, domain)
	}
	return w.Flush()
}

// Why: Sort domains in debug; consistent ordering aids in diffing files.
func writeDebugInvalidSources(filename string, invalidSources map[string][]string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "! Title: Debug Invalid Domains with Sources")
	fmt.Fprintf(w, "! Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "! Count: %d\n", len(invalidSources))
	fmt.Fprintln(w, "! Format: domain | source1,source2,...")

	domains := make([]string, 0, len(invalidSources))
	for d := range invalidSources {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		sources := invalidSources[domain]
		fmt.Fprintf(w, "%s | %s\n", domain, strings.Join(sources, ","))
	}
	return w.Flush()
}

// Why: Trim long lines; prevents debug overflow in consoles or files.
func trimLong(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
