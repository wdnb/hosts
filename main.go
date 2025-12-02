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

const (
	OutputFile      = "invalid_domains.txt"
	DebugFile       = "debug_invalid_sources.txt"
	UserAgent       = "AdGuard-HostlistCompiler-Go/1.0"
	UpstreamListURL = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"

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

var domainRegex = regexp.MustCompile(`^(?:\|\|)?([a-zA-Z0-9.-]+)(?:\^)?$`)
var hostRegex = regexp.MustCompile(`^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)`)

func main() {
	rand.Seed(time.Now().UnixNano())
	start := time.Now()
	fmt.Println(">>> 开始规则清洗与 DNS 无效检测...")

	upstreams, err := fetchUpstreamList(UpstreamListURL)
	if err != nil || len(upstreams) == 0 {
		fmt.Printf("!!! 无法获取上游源列表: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(">>> 成功加载 %d 个源\n", len(upstreams))

	availableChina := filterAvailableDNS(chinaDNS)
	availableGlobal := filterAvailableDNS(globalDNS)
	if len(availableChina) == 0 || len(availableGlobal) == 0 {
		fmt.Println("!!! 错误: 至少一个 DNS 列表无可用服务器")
		os.Exit(1)
	}

	limiters := make(map[string]*rate.Limiter)
	for _, s := range append(availableChina, availableGlobal...) {
		limiters[s] = rate.NewLimiter(rate.Limit(QPSPerServer), BurstPerServer)
	}

	ruleSources := downloadAndDeduplicate(upstreams)

	fmt.Printf(">>> 开始 DNS 验证 %d 条规则...\n", len(ruleSources))
	rules := make([]string, 0, len(ruleSources))
	for r := range ruleSources {
		rules = append(rules, r)
	}

	invalidDomains, invalidSources := checkDomainsForInvalid(rules, availableChina, availableGlobal, limiters, ruleSources)

	sort.Strings(invalidDomains)
	if err := writeInvalidToFile(OutputFile, invalidDomains); err != nil {
		fmt.Printf("!!! 写入失败: %v\n", err)
		os.Exit(1)
	}
	if err := writeDebugToFile(DebugFile, invalidSources); err != nil {
		fmt.Printf("!!! 写入 debug 文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(">>> 完成，总耗时: %v，无效域名: %d\n", time.Since(start), len(invalidDomains))
}

// ---------------------- 上游列表 ----------------------

func fetchUpstreamList(url string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
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

// ---------------------- DNS ----------------------

func filterAvailableDNS(servers []string) []string {
	var available []string
	for _, s := range servers {
		if checkDNSServer(s) {
			available = append(available, s)
		}
	}
	return available
}

func checkDNSServer(server string) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: DNSTimeout}).DialContext(ctx, "udp", server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
	defer cancel()
	ips, err := resolver.LookupHost(ctx, TestDomain)
	return err == nil && len(ips) > 0
}

// ---------------------- 下载与去重 ----------------------

func downloadAndDeduplicate(upstreams []string) map[string]map[string]struct{} {
	ruleSources := make(map[string]map[string]struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup

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
	return ruleSources
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
		if domain := parseLineToDomain(line); domain != "" {
			rules = append(rules, domain)
		}
	}
	return rules
}

// ---------------------- 规则解析 ----------------------

func parseLineToDomain(line string) string {
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return ""
	}

	if matches := domainRegex.FindStringSubmatch(line); len(matches) == 2 {
		domain := matches[1]
		if domain != "localhost" && domain != "local" && strings.Contains(domain, ".") {
			return domain
		}
	}
	if matches := hostRegex.FindStringSubmatch(line); len(matches) == 2 {
		domain := matches[1]
		if domain != "localhost" && domain != "local" && strings.Contains(domain, ".") {
			return domain
		}
	}
	return ""
}

// ---------------------- DNS 验证 ----------------------

func checkDomainsForInvalid(rules []string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter, ruleSources map[string]map[string]struct{}) ([]string, map[string][]string) {
	var invalid []string
	invalidSources := make(map[string][]string)
	var mu sync.Mutex

	jobs := make(chan string, len(rules))
	var wg sync.WaitGroup
	var processed int32
	total := int32(len(rules))

	for i := 0; i < MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				if !isDomainAlive(domain, availableChina, availableGlobal, limiters) {
					mu.Lock()
					invalid = append(invalid, domain)
					sources := make([]string, 0, len(ruleSources[domain]))
					for u := range ruleSources[domain] {
						sources = append(sources, u)
					}
					sort.Strings(sources)
					invalidSources[domain] = sources
					mu.Unlock()
				}

				curr := atomic.AddInt32(&processed, 1)
				if curr%5000 == 0 || curr == total {
					fmt.Printf("\r--> 进度: %d / %d (%.2f%%)", curr, total, float64(curr)/float64(total)*100)
				}
			}
		}()
	}

	for _, d := range rules {
		jobs <- d
	}
	close(jobs)
	wg.Wait()
	fmt.Println()
	return invalid, invalidSources
}

func isDefinitelyNXDomain(err error) bool {
	if err == nil {
		return false
	}
	dnsErr, ok := err.(*net.DNSError)
	return ok && (dnsErr.IsNotFound || strings.Contains(strings.ToLower(err.Error()), "no such host"))
}

func isDomainAlive(domain string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter) bool {
	allServers := append(availableChina[:], availableGlobal...)
	rand.Shuffle(len(allServers), func(i, j int) { allServers[i], allServers[j] = allServers[j], allServers[i] })
	for i := 0; i < 3 && i < len(allServers); i++ {
		server := allServers[i]
		if limiter := limiters[server]; limiter != nil {
			_ = limiter.Wait(context.Background())
		}

		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: DNSTimeout}).DialContext(ctx, "udp", server)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
		ips, err := resolver.LookupHost(ctx, domain)
		cancel()

		if err == nil && len(ips) > 0 {
			return true
		}
		if err != nil && isDefinitelyNXDomain(err) {
			continue
		}
		return true
	}
	return false
}

// ---------------------- 文件输出 ----------------------

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
