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
	OutputFile      = "invalid_domains.txt"
	DebugFile       = "debug_invalid_sources.txt"
	UserAgent       = "AdGuard-HostlistCompiler-Go/2.0"
	UpstreamListURL = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"

	MaxConcurrency = 1200
	DNSTimeout     = 1200 * time.Millisecond
	TestDomain     = "google.com"
	QPSPerServer   = 250
	BurstPerServer = 300
)

// 上游 DNS 服务器（国内 + 全球无过滤）
var chinaDNS = []string{
	"223.5.5.5:53", "223.6.6.6:53", "114.114.114.114:53", "114.114.115.115:53",
	"119.29.29.29:53", "180.76.76.76:53",
}

var globalDNS = []string{
	"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53",
	"9.9.9.9:53", "149.112.112.112:53",
	"94.140.14.140:53", "94.140.14.141:53", // AdGuard DNS Unfiltered
	"76.76.2.0:53", "76.76.10.0:53", // ControlD Unfiltered
	"208.67.222.222:53", "208.67.220.220:53", // OpenDNS
	"185.222.222.222:53", "45.11.45.11:53", // DNS.SB
	"216.146.35.35:53", "216.146.36.36:53", // Dyn
	"74.82.42.42:53", // Hurricane Electric
}

var (
	adguardRegex = regexp.MustCompile(`^\|\|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)\^`)
	hostsRegex   = regexp.MustCompile(`^(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]|::1)\s+([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)`)
	plainRegex   = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$`)
)

// -----------------------------------------------------------------------------
// 主函数
// -----------------------------------------------------------------------------
func main() {
	rand.Seed(time.Now().UnixNano())
	start := time.Now()
	fmt.Println(">>> [Init] 开始执行 AdGuard/Hosts 规则清洗 + DNS 无效域名检测")

	// 1. 获取上游源列表
	upstreams, err := fetchUpstreamList(UpstreamListURL)
	if err != nil || len(upstreams) == 0 {
		fmt.Printf("!!! 无法获取或解析上游列表: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(">>> [Upstream] 成功加载 %d 个源\n", len(upstreams))

	// 2. 预检测可用 DNS
	availableChina := filterAvailableDNS(chinaDNS)
	availableGlobal := filterAvailableDNS(globalDNS)
	if len(availableChina)+len(availableGlobal) == 0 {
		fmt.Println("!!! 所有 DNS 服务器都不可用，退出")
		os.Exit(1)
	}
	fmt.Printf(">>> [DNS] 可用服务器 → 中国 %d，全球 %d\n", len(availableChina), len(availableGlobal))

	// 3. 创建限速器
	limiters := make(map[string]*rate.Limiter)
	for _, s := range append(availableChina, availableGlobal...) {
		limiters[s] = rate.NewLimiter(rate.Limit(QPSPerServer), BurstPerServer)
	}

	// 4. 并发下载 + 直接提取裸域名 + 去重
	domainSources := make(map[string]map[string]struct{}) // domain → set[url]
	var mu sync.Mutex
	var wg sync.WaitGroup

	fmt.Printf(">>> [Download] 开始并发下载并提取域名（%d 个源）...\n", len(upstreams))
	for _, url := range upstreams {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			domains := downloadAndExtractDomains(u)
			if len(domains) == 0 {
				return
			}
			mu.Lock()
			for _, d := range domains {
				if _, ok := domainSources[d]; !ok {
					domainSources[d] = make(map[string]struct{})
				}
				domainSources[d][u] = struct{}{}
			}
			mu.Unlock()
		}(url)
	}
	wg.Wait()

	totalDomains := len(domainSources)
	fmt.Printf(">>> [Download] 完成！去重后共提取 %d 个唯一域名\n", totalDomains)

	// 5. DNS 无效检测
	fmt.Printf(">>> [DNS Check] 开始验证（并发 %d，超时 %v）...\n", MaxConcurrency, DNSTimeout)
	invalidDomains, debugInfo := checkDomainsAlive(domainSources, availableChina, availableGlobal, limiters)

	// 6. 输出结果
	validCount := totalDomains - len(invalidDomains)
	fmt.Printf(">>> [Result] 验证完成！有效域名: %d，无效域名: %d (%.2f%%)\n",
		validCount, len(invalidDomains), float64(len(invalidDomains))/float64(totalDomains)*100)

	sort.Strings(invalidDomains)
	if err := writeFile(OutputFile, generateInvalidList(invalidDomains)); err != nil {
		fmt.Printf("!!! 写入 %s 失败: %v\n", OutputFile, err)
	}
	if err := writeFile(DebugFile, generateDebugInfo(debugInfo)); err != nil {
		fmt.Printf("!!! 写入 %s 失败: %v\n", DebugFile, err)
	}

	fmt.Printf(">>> [Done] 全部完成，总耗时 %v\n", time.Since(start))
}

// -----------------------------------------------------------------------------
// 工具函数
// -----------------------------------------------------------------------------
func fetchUpstreamList(url string) ([]string, error) {
	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var list []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		list = append(list, line)
	}
	return list, sc.Err()
}

func filterAvailableDNS(servers []string) []string {
	var ok []string
	for _, s := range servers {
		if testDNS(s) {
			ok = append(ok, s)
		}
	}
	return ok
}

func testDNS(server string) bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: DNSTimeout}
			return d.DialContext(ctx, "udp", server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout*2)
	defer cancel()
	_, err := r.LookupHost(ctx, TestDomain)
	return err == nil
}

func httpGet(url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// 核心：直接提取干净域名（完全参考 wdnb/hosts 的成熟实现）
func extractCleanDomain(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
		return ""
	}
	line = strings.ToLower(line)

	if m := adguardRegex.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := hostsRegex.FindStringSubmatch(line); m != nil {
		d := m[1]
		if isLocalLikeDomain(d) {
			return ""
		}
		return d
	}
	if m := plainRegex.FindStringSubmatch(line); m != nil {
		d := m[1]
		if isLocalLikeDomain(d) {
			return ""
		}
		return d
	}
	return ""
}

func isLocalLikeDomain(d string) bool {
	switch d {
	case "localhost", "local", "localdomain", "broadcasthost",
		"ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix":
		return true
	}
	return strings.HasSuffix(d, ".local") ||
		strings.HasSuffix(d, ".lan") ||
		strings.HasSuffix(d, ".home") ||
		strings.HasSuffix(d, ".corp") ||
		strings.HasSuffix(d, ".invalid")
}

func downloadAndExtractDomains(url string) []string {
	resp, err := httpGet(url)
	if err != nil {
		fmt.Printf("!!! 下载失败 %s: %v\n", url, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Printf("!!! HTTP %d %s\n", resp.StatusCode, url)
		return nil
	}

	seen := make(map[string]struct{})
	var domains []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if d := extractCleanDomain(sc.Text()); d != "" {
			if _, exists := seen[d]; !exists {
				seen[d] = struct{}{}
				domains = append(domains, d)
			}
		}
	}
	return domains
}

func checkDomainsAlive(domainSources map[string]map[string]struct{},
	china, global []string, limiters map[string]*rate.Limiter) ([]string, map[string][]string) {

	var invalid []string
	debug := make(map[string][]string)
	var mu sync.Mutex
	var processed atomic.Int32
	total := int64(len(domainSources))

	jobs := make(chan string, 10000)
	var wg sync.WaitGroup

	for i := 0; i < MaxConcurrency; i++ {
		wg.Add(1)
		go worker(jobs, china, global, limiters, &processed, total, &invalid, debug, domainSources, &mu)
	}

	for domain := range domainSources {
		jobs <- domain
	}
	close(jobs)
	wg.Wait()

	return invalid, debug
}

func worker(jobs <-chan string,
	china, global []string, limiters map[string]*rate.Limiter,
	processed *atomic.Int32, total int64,
	invalid *[]string, debug map[string][]string,
	sources map[string]map[string]struct{}, mu *sync.Mutex) {

	defer wg.Done()

	all := append(china[:], global...)
	rand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })

	for domain := range jobs {
		if strings.Contains(domain, "*") || !strings.Contains(domain, ".") {
			processed.Add(1)
			continue
		}

		alive := false
		for i := 0; i < 3 && i < len(all); i++ {
			server := all[i]
			if l := limiters[server]; l != nil {
				_ = l.Wait(context.Background())
			}

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: DNSTimeout}
					return d.DialContext(ctx, "udp", server)
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
			ips, err := r.LookupHost(ctx, domain)
			cancel()

			if err == nil && len(ips) > 0 {
				alive = true
				break
			}
			if isNXDomain(err) {
				continue // 明确不存在，继续下一个 DNS
			}
			// 超时/网络错误/ServFail 等 → 保守认为可能存在
			alive = true
			break
		}

		if !alive {
			mu.Lock()
			invalid = append(invalid, domain)
			srcs := make([]string, 0, len(sources[domain]))
			for u := range sources[domain] {
				srcs = append(srcs, u)
			}
			sort.Strings(srcs)
			debug[domain] = srcs
			mu.Unlock()
		}

		cur := processed.Add(1)
		if cur%8000 == 0 || cur == total {
			fmt.Printf("\r--> 已处理: %d / %d (%.2f%%)", cur, total, float64(cur)/float64(total)*100)
		}
	}
}

func isNXDomain(err error) bool {
	if err == nil {
		return false
	}
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound || strings.Contains(dnsErr.Error(), "no such host")
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}

func writeFile(filename string, content string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func generateInvalidList(domains []string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("! Title: DNS Invalid Domains (Checked %s)\n", time.Now().Format("2006-01-02 15:04")))
	sb.WriteString(fmt.Sprintf("! Total invalid: %d\n", len(domains)))
	sb.WriteString("!\n")
	for _, d := range domains {
		sb.WriteString(d + "\n")
	}
	return sb.String()
}

func generateDebugInfo(m map[string][]string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("! Debug: Invalid Domains & Sources (%s)\n", time.Now().Format("2006-01-02 15:04")))
	sb.WriteString(fmt.Sprintf("! Count: %d\n", len(m)))
	sb.WriteString("! Format: domain | source1,source2,...\n\n")

	list := make([]string, 0, len(m))
	for d := range m {
		list = append(list, d)
	}
	sort.Strings(list)

	for _, d := range list {
		sb.WriteString(fmt.Sprintf("%s | %s\n", d, strings.Join(m[d], ",")))
	}
	return sb.String()
}
