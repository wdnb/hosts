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
// 配置区域（关键修改在这里）
// -----------------------------------------------------------------------------

const (
	OutputFile      = "invalid_domains.txt"
	DebugFile       = "debug_invalid_sources.txt"
	UserAgent       = "AdGuard-HostlistCompiler-Go/1.0"
	UpstreamListURL = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"
	// 资源控制
	MaxConcurrency = 1000
	DNSTimeout     = 1000 * time.Millisecond
	TestDomain     = "google.com"
	QPSPerServer   = 200
	BurstPerServer = 200
)

// 上游 DNS 服务器
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

var domainExtractRegex = regexp.MustCompile(`^\|\|([a-zA-Z0-9.-]+)\^$`)
var hostExtractRegex = regexp.MustCompile(`^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)`)

// -----------------------------------------------------------------------------
// 主函数
// -----------------------------------------------------------------------------
func main() {
	rand.Seed(time.Now().UnixNano())
	start := time.Now()
	fmt.Println(">>> [Init] 开始执行规则清洗与 DNS 无效检测...")

	// 1. 从上游获取真正的源列表
	upstreams, err := fetchUpstreamList(UpstreamListURL)
	if err != nil {
		fmt.Printf("!!! 无法获取上游源列表 %s: %v\n", UpstreamListURL, err)
		os.Exit(1)
	}
	if len(upstreams) == 0 {
		fmt.Println("!!! 上游源列表为空，退出")
		os.Exit(1)
	}
	fmt.Printf(">>> [Upstream] 从 %s 成功加载 %d 个源\n", UpstreamListURL, len(upstreams))

	// 2. 预检查 DNS 可用性
	availableChina := filterAvailableDNS(chinaDNS)
	availableGlobal := filterAvailableDNS(globalDNS)
	if len(availableChina) == 0 || len(availableGlobal) == 0 {
		fmt.Println("!!! 错误: 至少一个 DNS 列表无可用服务器 (China:", len(availableChina), ", Global:", len(availableGlobal), ")")
		os.Exit(1)
	}
	fmt.Printf(">>> [DNS Precheck] 可用 DNS - China: %d, Global: %d\n", len(availableChina), len(availableGlobal))

	// 3. 创建限速器
	limiters := make(map[string]*rate.Limiter)
	for _, s := range append(availableChina, availableGlobal...) {
		limiters[s] = rate.NewLimiter(rate.Limit(QPSPerServer), BurstPerServer)
	}

	// 4. 下载并去重
	ruleSources := make(map[string]map[string]struct{}) // rule -> set of upstream URLs
	var mu sync.Mutex
	var wg sync.WaitGroup

	fmt.Printf(">>> [Download] 开始并发下载 %d 个源...\n", len(upstreams))

	for _, url := range upstreams {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			rules := downloadAndParse(u)
			if rules == nil {
				return
			}
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

	// 5. DNS 无效检测
	checkQueue := make([]string, 0, totalRaw)
	for r := range ruleSources {
		checkQueue = append(checkQueue, r)
	}

	fmt.Printf(">>> [DNS Check] 开始 DNS 验证 (并发: %d, 超时: %v)...\n", MaxConcurrency, DNSTimeout)
	invalidDomains, invalidSources := checkDomainsForInvalid(checkQueue, availableChina, availableGlobal, limiters, ruleSources)

	// 6. 输出结果
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
// 新增：从上游获取源列表
// -----------------------------------------------------------------------------
func fetchUpstreamList(url string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var list []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		list = append(list, line)
	}
	return list, scanner.Err()
}

func filterAvailableDNS(servers []string) []string {
	var available []string
	for _, server := range servers {
		if checkDNSServer(server) {
			available = append(available, server)
		}
	}
	return available
}

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
		fmt.Printf("!!! 下载失败 [%s]: HTTP %d\n", url, resp.StatusCode)
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

func checkDomainsForInvalid(rules []string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter, ruleSources map[string]map[string]struct{}) ([]string, map[string][]string) {
	var invalidDomains []string
	var invalidSources = make(map[string][]string)
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
					sort.Strings(sources)
					invalidSources[domain] = sources
					mu.Unlock()
				}

				current := atomic.AddInt32(&processedCount, 1)
				if current%5000 == 0 || current == total {
					fmt.Printf("\r--> 进度: %d / %d (%.2f%%)", current, total, float64(current)/float64(total)*100)
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

func extractDomain(rule string) string {
	if strings.HasPrefix(rule, "||") && strings.HasSuffix(rule, "^") {
		return rule[2 : len(rule)-1]
	}
	return ""
}

func isDomainAlive(domain string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter) bool {
	lists := [][]string{availableChina, availableGlobal}
	initialIdx := rand.Intn(2)
	if tryList(lists[initialIdx], domain, limiters) {
		return true
	}
	return tryList(lists[1-initialIdx], domain, limiters)
}

func tryList(servers []string, domain string, limiters map[string]*rate.Limiter) bool {
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
	for _, d := range domains {
		fmt.Fprintln(w, d)
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

	domains := make([]string, 0, len(invalidSources))
	for d := range invalidSources {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	for _, d := range domains {
		fmt.Fprintf(w, "%s | %s\n", d, strings.Join(invalidSources[d], ","))
	}
	return w.Flush()
}
