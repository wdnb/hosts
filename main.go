package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// -----------------------------------------------------------------------------
// 配置区域
// -----------------------------------------------------------------------------

const (
	OutputFile = "invalid_domains.txt"
	DebugFile  = "debug_invalid_sources.txt"
	UserAgent  = "AdGuard-HostlistCompiler-Go/1.0"

	// 资源控制
	MaxConcurrency = 500                     // 限制并发查询数量
	DNSTimeout     = 1000 * time.Millisecond // DNS 超时时间，遵循 Fail Fast 原则

	// 测试 DNS 可用性的已知域名
	TestDomain = "google.com"

	// 每个 DNS 服务器的速率限制
	QPSPerServer   = 200
	BurstPerServer = 200
)

// 上游 DNS 服务器列表，分成中国和全球两部分
var chinaDNS = []string{
	"223.5.5.5:53",       // AliDNS Primary
	"223.6.6.6:53",       // AliDNS Secondary
	"114.114.114.114:53", // 114DNS Primary
	"114.114.115.115:53", // 114DNS Secondary
	"180.76.76.76:53",    // Baidu DNS
	"119.29.29.29:53",    // DNSPod (Tencent)
	"182.254.116.116:53", // Tencent DNS
}

var globalDNS = []string{
	"1.1.1.1:53",         // Cloudflare Primary
	"1.0.0.1:53",         // Cloudflare Secondary
	"8.8.8.8:53",         // Google Primary
	"8.8.4.4:53",         // Google Secondary
	"9.9.9.9:53",         // Quad9 Primary
	"149.112.112.112:53", // Quad9 Secondary
	"208.67.222.222:53",  // OpenDNS Primary
	"208.67.220.220:53",  // OpenDNS Secondary
}

// 源列表
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
// 核心逻辑
// -----------------------------------------------------------------------------

// 提取域名的正则 (AdGuard 格式 ||domain^ -> domain)
// 这是一个简化版本，旨在提取用于 DNS 验证的主机名
var domainExtractRegex = regexp.MustCompile(`^\|\|([a-zA-Z0-9.-]+)\^$`)
var hostExtractRegex = regexp.MustCompile(`^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)`)

func main() {
	rand.Seed(time.Now().UnixNano()) // 初始化随机种子
	start := time.Now()
	fmt.Println(">>> [Init] 开始执行规则清洗与 DNS 无效检测...")

	// 预检查 DNS 服务器可用性
	availableChina := filterAvailableDNS(chinaDNS)
	availableGlobal := filterAvailableDNS(globalDNS)

	if len(availableChina) == 0 || len(availableGlobal) == 0 {
		fmt.Println("!!! 错误: 至少一个 DNS 列表无可用服务器 (China:", len(availableChina), ", Global:", len(availableGlobal), ")")
		os.Exit(1)
	}

	fmt.Printf(">>> [DNS Precheck] 可用 DNS - China: %d, Global: %d\n", len(availableChina), len(availableGlobal))

	// 为每个可用 DNS 服务器创建速率限制器 (200 QPS)
	limiters := make(map[string]*rate.Limiter)
	for _, s := range append(availableChina, availableGlobal...) {
		limiters[s] = rate.NewLimiter(rate.Limit(QPSPerServer), BurstPerServer)
	}

	// 1. 下载并初步清洗 (Map 去重，同时记录来源)
	ruleSources := make(map[string]map[string]struct{}) // rule -> set of upstream URLs
	var mu sync.Mutex
	var wg sync.WaitGroup

	fmt.Printf(">>> [Download] 正在并发下载 %d 个源...\n", len(Upstreams))

	for _, url := range Upstreams {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			rules := downloadAndParse(u)
			mu.Lock()
			for _, r := range rules {
				if _, ok := ruleSources[r]; !ok {
					ruleSources[r] = make(map[string]struct{})
				}
				ruleSources[r][u] = struct{}{}
			}
			mu.Unlock()
		}(url)
	}
	wg.Wait()

	totalRaw := len(ruleSources)
	fmt.Printf(">>> [Download] 下载完成。去重后原始规则数: %d\n", totalRaw)

	// 2. DNS 无效检测
	checkQueue := make([]string, 0, totalRaw)
	for r := range ruleSources {
		checkQueue = append(checkQueue, r)
	}

	fmt.Printf(">>> [DNS Check] 开始 DNS 验证 (并发数: %d, 超时: %v, QPS/服务器: %d, 使用随机上游 DNS 列表)...\n", MaxConcurrency, DNSTimeout, QPSPerServer)

	invalidDomains, invalidSources := checkDomainsForInvalid(checkQueue, availableChina, availableGlobal, limiters, ruleSources)

	// 3. 排序与输出
	fmt.Printf(">>> [Output] 验证完成。无效域名: %d (有效规则: %d)\n", len(invalidDomains), totalRaw-len(invalidDomains))

	sort.Strings(invalidDomains)
	if err := writeInvalidToFile(OutputFile, invalidDomains); err != nil {
		fmt.Printf("!!! 写入失败: %v\n", err)
		os.Exit(1)
	}

	if err := writeDebugToFile(DebugFile, invalidSources); err != nil {
		fmt.Printf("!!! 写入 debug 文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(">>> [Done] 全部完成，总耗时: %v\n", time.Since(start))
}

// -----------------------------------------------------------------------------
// 功能函数
// -----------------------------------------------------------------------------

// filterAvailableDNS 过滤可用 DNS 服务器
func filterAvailableDNS(servers []string) []string {
	var available []string
	for _, server := range servers {
		if checkDNSServer(server) {
			available = append(available, server)
		}
	}
	return available
}

// checkDNSServer 检查 DNS 服务器是否可用（通过解析已知域名）
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

func downloadAndParse(url string) []string {
	client := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("!!! 下载失败 [%s]: %v\n", url, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	var rules []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if cleaned := normalize(line); cleaned != "" {
			rules = append(rules, cleaned)
		}
	}
	return rules
}

// normalize 标准化规则，统一转为 AdGuard 格式 ||domain^
func normalize(line string) string {
	if len(line) < 4 || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
		return ""
	}

	line = strings.ToLower(line)

	if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
		return line
	}

	if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			domain := parts[1]
			if domain != "localhost" && domain != "local" {
				return "||" + domain + "^"
			}
		}
	}

	return ""
}

// checkDomainsForInvalid 使用 Worker Pool 模式进行 DNS 验证，收集无效域名
func checkDomainsForInvalid(rules []string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter, ruleSources map[string]map[string]struct{}) ([]string, map[string][]string) {
	var invalidDomains []string
	var invalidSources = make(map[string][]string) // domain -> list of sources
	var mu sync.Mutex

	jobs := make(chan string, len(rules))
	var wg sync.WaitGroup

	var processedCount int32
	total := int32(len(rules))

	for i := 0; i < MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rule := range jobs {
				domain := extractDomain(rule)

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
					sort.Strings(sources) // 可选排序来源
					invalidSources[domain] = sources
					mu.Unlock()
				}

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

// extractDomain 从规则中提取纯域名用于 DNS 查询
func extractDomain(rule string) string {
	if strings.HasPrefix(rule, "||") && strings.HasSuffix(rule, "^") {
		return rule[2 : len(rule)-1]
	}
	return ""
}

// isDomainAlive 执行实际的 DNS 查询，支持重试另一列表
func isDomainAlive(domain string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter) bool {
	lists := [][]string{availableChina, availableGlobal}
	initialIdx := rand.Intn(2)
	otherIdx := 1 - initialIdx

	// 尝试初始列表
	if tryList(lists[initialIdx], domain, limiters) {
		return true
	}

	// 重试另一列表
	return tryList(lists[otherIdx], domain, limiters)
}

// tryList 使用指定列表中的随机服务器尝试解析域名
func tryList(servers []string, domain string, limiters map[string]*rate.Limiter) bool {
	if len(servers) == 0 {
		return false // 不过预检查已确保非空
	}

	idx := rand.Intn(len(servers))
	server := servers[idx]

	// 应用速率限制
	limiter := limiters[server]
	if err := limiter.Wait(context.Background()); err != nil {
		return false // 如果限速失败，视作无效（罕见）
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

func writeDebugToFile(filename string, invalidSources map[string][]string) error {
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

	// 排序域名以一致输出
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
