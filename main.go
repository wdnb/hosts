package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

const (
	OutputFile      = "invalid_domains.txt"
	DebugFile       = "debug_invalid_sources.txt"
	UserAgent       = "AdGuard-HostlistCompiler-Go/2.0-Optimized"
	UpstreamListURL = "https://raw.githubusercontent.com/wdnb/hosts/refs/heads/main/upstream_list.txt"

	// 性能调优参数
	// 压榨性能：提高并发数，依赖 RateLimiter 进行流控
	MaxConcurrency = 5000
	// 缩短超时时间，快速失败重试
	DNSTimeout = 800 * time.Millisecond
	TestDomain = "google.com"
	// 针对公共 DNS，适当保守以免被封禁，但总量足够大
	QPSPerServer   = 150
	BurstPerServer = 200
)

// DNS 服务器列表保持不变...
var chinaDNS = []string{
	"223.5.5.5:53", "223.6.6.6:53", "114.114.114.114:53", "114.114.115.115:53",
	"180.76.76.76:53", "119.29.29.29:53", "182.254.116.116:53",
}

var globalDNS = []string{
	"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53",
	"9.9.9.9:53", "149.112.112.112:53", "208.67.222.222:53", "208.67.220.220:53",
	"94.140.14.140:53", "94.140.14.141:53",
	"208.67.222.2:53", "208.67.220.2:53",
	"76.76.2.0:53", "76.76.10.0:53",
	"185.222.222.222:53", "45.11.45.11:53",
	"54.174.40.213:53", "52.3.100.184:53",
	"216.146.35.35:53", "216.146.36.36:53",
	"80.80.80.80:53", "80.80.81.81:53",
	"74.82.42.42:53",
}

var (
	domainRegex = regexp.MustCompile(`^(?:\|\|)?([a-zA-Z0-9.-]+)(?:\^)?$`)
	hostRegex   = regexp.MustCompile(`^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)`)
)

// Shared DNS Client to reuse sockets where possible and reduce GC
var dnsClient = &dns.Client{
	Timeout: DNSTimeout,
	Net:     "udp",
	// 禁用 UDP 大小检查，追求速度
	UDPSize: 4096,
}

func main() {
	rand.Seed(time.Now().UnixNano())
	start := time.Now()
	fmt.Println(">>> [Init] 开始规则清洗与高性能 DNS 检测...")

	// 1. 获取上游
	upstreams, err := fetchUpstreamList(UpstreamListURL)
	if err != nil || len(upstreams) == 0 {
		fmt.Printf("!!! [Error] 无法获取上游源列表: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(">>> [Source] 成功加载 %d 个源\n", len(upstreams))

	// 2. 检测并筛选可用 DNS
	fmt.Println(">>> [DNS] 正在筛选可用 DNS 服务器...")
	availableChina := filterAvailableDNS(chinaDNS)
	availableGlobal := filterAvailableDNS(globalDNS)

	totalServers := len(availableChina) + len(availableGlobal)
	if totalServers == 0 {
		fmt.Println("!!! [Error] 无任何可用 DNS 服务器，请检查网络")
		os.Exit(1)
	}
	fmt.Printf(">>> [DNS] 可用服务器: China=%d, Global=%d, Total=%d\n", len(availableChina), len(availableGlobal), totalServers)

	// 3. 初始化限流器
	limiters := make(map[string]*rate.Limiter)
	for _, s := range append(availableChina, availableGlobal...) {
		limiters[s] = rate.NewLimiter(rate.Limit(QPSPerServer), BurstPerServer)
	}

	// 4. 下载去重
	ruleSources := downloadAndDeduplicate(upstreams)
	fmt.Printf(">>> [Rules] 唯一规则数: %d\n", len(ruleSources))

	rules := make([]string, 0, len(ruleSources))
	for r := range ruleSources {
		rules = append(rules, r)
	}

	// 5. 核心：高并发 DNS 验证
	invalidDomains, invalidSources := checkDomainsForInvalid(rules, availableChina, availableGlobal, limiters, ruleSources)

	// 6. 输出结果
	sort.Strings(invalidDomains)
	if err := writeInvalidToFile(OutputFile, invalidDomains); err != nil {
		fmt.Printf("!!! [Error] 写入失败: %v\n", err)
		os.Exit(1)
	}
	if err := writeDebugToFile(DebugFile, invalidSources); err != nil {
		fmt.Printf("!!! [Error] 写入 debug 文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n>>> [Done] 总耗时: %v | 无效域名: %d | 有效保留: %d\n", time.Since(start), len(invalidDomains), len(rules)-len(invalidDomains))
}

// ---------------------- DNS 核心逻辑 (重构部分) ----------------------

// filterAvailableDNS 使用 miekg/dns 进行快速握手检测
func filterAvailableDNS(servers []string) []string {
	var available []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, s := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			// 严格检查：必须能解析 google.com 且返回 NOERROR
			if checkDNSServerStrict(server) {
				mu.Lock()
				available = append(available, server)
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()
	return available
}

func checkDNSServerStrict(server string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(TestDomain), dns.TypeA)
	// 使用一次性 client 避免污染全局配置，但复用超时逻辑
	c := &dns.Client{Timeout: DNSTimeout, Net: "udp"}
	r, _, err := c.Exchange(m, server)

	// 逻辑完备性：必须没有网络错误，且 Rcode 为 Success，且有 Answer
	if err == nil && r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		return true
	}
	return false
}

func checkDomainsForInvalid(rules []string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter, ruleSources map[string]map[string]struct{}) ([]string, map[string][]string) {
	var invalid []string
	invalidSources := make(map[string][]string)
	var mu sync.Mutex

	// 任务通道
	jobs := make(chan string, 10000) // 增大 buffer 防止阻塞
	var wg sync.WaitGroup

	// 进度条计数
	var processed int64
	total := int64(len(rules))

	// 启动高并发 Worker
	// 这里的并发数不仅是本地 CPU 的并发，更是为了填满 DNS 服务器的 RTT 等待时间
	for i := 0; i < MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// 预分配 Message 对象，在循环中 Reset，减少内存分配
			m := new(dns.Msg)

			for domain := range jobs {
				// isDomainDead 返回 true 表示确定已死 (NXDOMAIN)
				// 返回 false 表示活着或者无法确定（保守保留）
				if isDomainDead(domain, availableChina, availableGlobal, limiters, m) {
					mu.Lock()
					invalid = append(invalid, domain)
					// 记录来源用于 Debug
					sources := make([]string, 0, len(ruleSources[domain]))
					for u := range ruleSources[domain] {
						sources = append(sources, u)
					}
					// 仅在 debug 输出时排序，减少锁内耗时
					invalidSources[domain] = sources
					mu.Unlock()
				}

				curr := atomic.AddInt64(&processed, 1)
				if curr%2000 == 0 || curr == total {
					fmt.Printf("\r--> 进度: %d / %d (%.2f%%) | 当前无效: %d", curr, total, float64(curr)/float64(total)*100, len(invalid))
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

	// 最后再对 debug source 进行一次整体排序，避免在并发锁中进行
	for k := range invalidSources {
		sort.Strings(invalidSources[k])
	}

	return invalid, invalidSources
}

// isDomainDead 判断逻辑核心
// 返回 true:  确信域名已死 (NXDOMAIN)
// 返回 false: 域名存活 (NOERROR + Answer) 或 无法确定 (SERVFAIL/REFUSED/TIMEOUT) -> 保守策略: 视为存活
func isDomainDead(domain string, availableChina, availableGlobal []string, limiters map[string]*rate.Limiter, m *dns.Msg) bool {
	// 构造完整域名
	fqdn := dns.Fqdn(domain)

	// 混合服务器列表，每次随机打乱以负载均衡
	// 优化：不每次创建新切片，使用随机索引访问
	allServers := append(availableChina, availableGlobal...) // 这里的 append 仍然有开销，但对于数百万次调用可接受，也可优化为全局 slice

	// 尝试次数：最多尝试 3 个不同的服务器
	// 如果遇到 REFUSED/SERVFAIL，我们需要换一个服务器再试，不能立即判死
	maxRetries := 3

	// Fisher-Yates shuffle 的简化版，只随机选前 maxRetries 个
	perm := rand.Perm(len(allServers))

	nxDomainCount := 0

	for i := 0; i < maxRetries && i < len(allServers); i++ {
		server := allServers[perm[i]]

		// 1. 获取令牌 (流量整形核心)
		if limiter, ok := limiters[server]; ok {
			// Wait 会阻塞直到拿到令牌，这是并发控制的关键
			if err := limiter.Wait(context.Background()); err != nil {
				continue // 理论上不应发生，除非 context 取消
			}
		}

		// 2. 构造查询
		m.SetQuestion(fqdn, dns.TypeA) // 只查 A 记录，最快
		// 可以在这里加 TypeAAAA 逻辑，但通常广告域名 A 记录没了就是没了

		// 3. 发送请求 (使用全局 client)
		r, _, err := dnsClient.Exchange(m, server)

		// 4. 逻辑判决
		if err != nil {
			// 网络层面的错误 (Timeout, Network Unreachable, EOF)
			// 这不代表域名不存在，代表网络或服务器有问题 -> 换个服务器重试
			continue
		}

		if r == nil {
			continue
		}

		switch r.Rcode {
		case dns.RcodeSuccess:
			// 即使是 Success，也要看有没有 Answer
			if len(r.Answer) > 0 {
				return false // 活着！
			}
			// NOERROR 但没有 Answer (NODATA)。
			// 可能是 CNAME 指向空，或者是仅有 AAAA 记录。
			// 严格来说这不算 NXDOMAIN，不能删。 -> 视为存活
			return false

		case dns.RcodeNameError:
			// NXDOMAIN: 权威告知域名不存在。
			// 为了防止某个递归 DNS 抽风，我们可以选择立即判死，或者计数
			// 在大批量清洗中，只要有一个可信 DNS 说 NXDOMAIN，通常就是挂了
			// 激进策略：立即返回 true
			// return true
			// 保守策略（可选）：
			nxDomainCount++
			if nxDomainCount > 1 {
				return true
			}

		case dns.RcodeServerFailure, dns.RcodeRefused:
			// 服务器挂了或拒绝服务。绝对不能判死。
			// 必须重试下一个服务器。
			continue

		default:
			// 其他错误 (FormatError, NotImplemented 等)，保守处理，视为重试或忽略
			continue
		}
	}

	// 如果循环结束了：
	// 1. 所有的尝试都 Timeout/Refused 了 -> 无法验证 -> 保守策略：不删 (return false)
	// 2. 所有的尝试都没有 Answer 但也不是 NXDOMAIN -> 保守策略：不删 (return false)

	// 这里体现了 skepticism：如果我不确定它死了，那它就是活的。
	return false
}

// ---------------------- 辅助函数 (基本保持不变或微调) ----------------------

func fetchUpstreamList(url string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var list []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") {
			list = append(list, line)
		}
	}
	return list, scanner.Err()
}

func downloadAndDeduplicate(upstreams []string) map[string]map[string]struct{} {
	ruleSources := make(map[string]map[string]struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 限制下载并发数，防止带宽占满导致 DNS 失败
	sem := make(chan struct{}, 5)

	for _, url := range upstreams {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

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
		fmt.Printf("!!! [Download] 失败 [%s]: %v\n", url, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Printf("!!! [Download] 状态码错误 [%s]: HTTP %d\n", url, resp.StatusCode)
		return nil
	}

	var rules []string
	scanner := bufio.NewScanner(resp.Body)
	// 增大 scanner buffer 应对超长行
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if domain := parseLineToDomain(line); domain != "" {
			rules = append(rules, domain)
		}
	}
	return rules
}

func parseLineToDomain(line string) string {
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return ""
	}
	// 优化：先尝试最常见的 host 格式，再尝试 adblock 格式，减少正则回溯
	if matches := hostRegex.FindStringSubmatch(line); len(matches) == 2 {
		domain := matches[1]
		if domain != "localhost" && domain != "local" && strings.Contains(domain, ".") {
			return domain
		}
	}
	if matches := domainRegex.FindStringSubmatch(line); len(matches) == 2 {
		domain := matches[1]
		if domain != "localhost" && domain != "local" && strings.Contains(domain, ".") {
			return domain
		}
	}
	return ""
}

func writeInvalidToFile(filename string, domains []string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "! Title: Invalid Domains List (Strict DNS Check)")
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
