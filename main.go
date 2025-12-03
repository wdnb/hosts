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

	// --- 性能与并发调优 ---
	// 为什么设置 5000 并发？
	// DNS 请求是 IO 密集型而非 CPU 密集型。我们需要大量的 Goroutine 来填满
	// DNS 服务器响应的 RTT (Round Trip Time) 空隙，从而最大化吞吐量。
	// 实际流量由 RateLimiter 控制，不会导致洪水攻击。
	MaxConcurrency = 5000

	// 为什么是 800ms？
	// 绝大多数正常的 DNS 响应都在 200ms 内。
	// 设置过长的超时会导致 Worker 被慢速服务器卡住，降低整体处理速度。
	// 我们宁愿快速失败并重试另一个服务器，也不愿长时间等待。
	DNSTimeout = 800 * time.Millisecond

	TestDomain = "google.com"

	// 为什么限制 QPS？
	// 公共 DNS 通常有防滥用机制。如果不加限制，我们的 IP 会被暂时封禁（返回 REFUSED）。
	// 150 QPS 是一个在速度和稳定性之间的平衡值。
	QPSPerServer   = 150
	BurstPerServer = 200
)

// DefaultDNSList 包含国内外混合的高可用 DNS。
// 为什么混合？
// 我们不依赖单一地区的解析结果。通过混合列表并随机选择，可以避免因单一地区网络波动
// 或特定运营商污染导致的误判，同时利用全球 CDN 节点的响应速度。
var DefaultDNSList = []string{
	// Global unfiltered (no malware/ad/tracking blocking)
	"1.1.1.1:53", "1.0.0.1:53", // Cloudflare DNS (neutral, no filtering)
	"8.8.8.8:53", "8.8.4.4:53", // Google Public DNS (neutral, no filtering)
	"9.9.9.10:53", "149.112.112.10:53", // Quad9 (unfiltered/malware-off variant)
	"208.67.222.2:53", "208.67.220.2:53", // Cisco OpenDNS Sandbox (unfiltered)
	"94.140.14.140:53", "94.140.14.141:53", // AdGuard DNS Non-filtering
	"76.76.2.0:53", "76.76.10.0:53", // ControlD Unfiltered
	"156.154.70.1:53", "156.154.71.1:53", // Neustar/UltraDNS Reliability & Performance 1 (neutral)
	"156.154.70.5:53", "156.154.71.5:53", // Neustar/UltraDNS Reliability & Performance 2 (neutral, no NXDomain redirection)
	"77.88.8.8:53", "77.88.8.1:53", // Yandex DNS Basic (no filtering)
	"86.54.11.100:53", "86.54.11.200:53", // DNS4EU Unfiltered
	"185.222.222.222:53", "45.11.45.11:53", // DNS.SB (neutral, no filtering)
	"80.80.80.80:53", "80.80.81.81:53", // Freenom World (neutral)
	"64.6.64.6:53", "64.6.65.6:53", // Verisign Public DNS (neutral)
	"74.82.42.42:53", // Hurricane Electric (neutral)
}

var (
	// 为什么用两个正则？
	// 能够同时兼容 "/etc/hosts" 格式 (0.0.0.0 domain) 和 AdBlock 格式 (||domain^)。
	domainRegex = regexp.MustCompile(`^(?:\|\|)?([a-zA-Z0-9.-]+)(?:\^)?$`)
	hostRegex   = regexp.MustCompile(`^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)`)
)

// 复用 client 以减少 socket 创建销毁的系统调用开销和 GC 压力
var dnsClient = &dns.Client{
	Timeout: DNSTimeout,
	Net:     "udp",
	UDPSize: 4096,
}

func main() {
	rand.Seed(time.Now().UnixNano())
	start := time.Now()
	fmt.Println(">>> [Init] 开始规则清洗与高性能 DNS 检测...")

	// 1. 获取上游规则源
	upstreams, err := fetchUpstreamList(UpstreamListURL)
	if err != nil || len(upstreams) == 0 {
		fmt.Printf("!!! [Error] 无法获取上游源列表: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(">>> [Source] 成功加载 %d 个源\n", len(upstreams))

	// 2. 预检 DNS 服务器
	// 为什么要在开始前检查？
	// 避免将损坏的或不可达的 DNS 服务器加入池中，这会浪费重试次数并拖慢整体扫描速度。
	fmt.Println(">>> [DNS] 正在筛选可用 DNS 服务器...")
	validDNS := filterAvailableDNS(DefaultDNSList)

	if len(validDNS) == 0 {
		fmt.Println("!!! [Error] 无任何可用 DNS 服务器，请检查网络连接")
		os.Exit(1)
	}
	fmt.Printf(">>> [DNS] 存活服务器: %d 个\n", len(validDNS))

	// 3. 初始化限流器
	// 为每个 DNS 服务器分配独立的令牌桶，确保单个服务器的负载均衡，防止被特定服务商封禁。
	limiters := make(map[string]*rate.Limiter)
	for _, s := range validDNS {
		limiters[s] = rate.NewLimiter(rate.Limit(QPSPerServer), BurstPerServer)
	}

	// 4. 下载并去重规则
	ruleSources := downloadAndDeduplicate(upstreams)
	fmt.Printf(">>> [Rules] 唯一规则数: %d\n", len(ruleSources))

	rules := make([]string, 0, len(ruleSources))
	for r := range ruleSources {
		rules = append(rules, r)
	}

	// 5. 执行核心检测
	invalidDomains, invalidSources := checkDomainsForInvalid(rules, validDNS, limiters, ruleSources)

	// 6. 结果输出
	// 对结果排序，保证每次运行生成的 diff 最小化，便于 Git 版本控制。
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

// ---------------------- DNS 核心逻辑 ----------------------

func filterAvailableDNS(servers []string) []string {
	var available []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, s := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			// 严格模式：只有当 DNS 服务器能正确解析标杆域名 (google.com) 时才视为可用。
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
	// 使用一次性 client 避免并发干扰，但复用超时配置
	c := &dns.Client{Timeout: DNSTimeout, Net: "udp"}
	r, _, err := c.Exchange(m, server)

	// 逻辑完备性检查：
	// 1. err == nil: 网络通畅。
	// 2. r.Rcode == Success: 服务器状态正常（非 REFUSED/SERVFAIL）。
	// 3. len(r.Answer) > 0: 服务器没有对标杆域名进行劫持或过滤（返回空 IP）。
	if err == nil && r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		return true
	}
	return false
}

func checkDomainsForInvalid(rules []string, dnsServers []string, limiters map[string]*rate.Limiter, ruleSources map[string]map[string]struct{}) ([]string, map[string][]string) {
	var invalid []string
	invalidSources := make(map[string][]string)
	var mu sync.Mutex

	jobs := make(chan string, 10000)
	var wg sync.WaitGroup
	var processed int64
	total := int64(len(rules))

	// 启动 Worker 池
	for i := 0; i < MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 在循环外分配 Msg 对象，循环内 Reset，极大减少内存分配频率 (GC 优化)
			m := new(dns.Msg)

			for domain := range jobs {
				// 只有当 isDomainDead 明确返回 true 时，才将其加入无效列表。
				// 任何不确定性（超时、服务器拒绝）都默认为“域名存活”，遵循 Fail-Safe 原则。
				if isDomainDead(domain, dnsServers, limiters, m) {
					mu.Lock()
					invalid = append(invalid, domain)
					// 仅在确认无效时才进行来源数据的聚合操作
					sources := make([]string, 0, len(ruleSources[domain]))
					for u := range ruleSources[domain] {
						sources = append(sources, u)
					}
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

	// 统一在最后进行排序，避免在 Worker 锁中进行 O(N*logN) 操作，减少锁竞争时间
	for k := range invalidSources {
		sort.Strings(invalidSources[k])
	}

	return invalid, invalidSources
}

// isDomainDead 是判断域名生死的最终仲裁者
// 返回 true: 确信域名不存在 (NXDOMAIN)。
// 返回 false: 域名解析成功，或因网络/服务器问题无法确定（保守保留）。
func isDomainDead(domain string, servers []string, limiters map[string]*rate.Limiter, m *dns.Msg) bool {
	fqdn := dns.Fqdn(domain)
	maxRetries := 3

	// 为什么要 Shuffle？
	// 防止“热点效应”。如果所有 Worker 都按顺序请求 Server A，Server A 的限流桶会瞬间耗尽，
	// 导致大量协程阻塞等待，而 Server B 却闲置。随机化保证了负载在所有可用 DNS 间均匀分布。
	// 使用 Perm 获取随机索引比每次 copy slice 性能更好。
	perm := rand.Perm(len(servers))

	for i := 0; i < maxRetries && i < len(servers); i++ {
		server := servers[perm[i]]

		// 流量控制：严格遵守该 DNS 服务器的速率限制
		if limiter, ok := limiters[server]; ok {
			if err := limiter.Wait(context.Background()); err != nil {
				continue
			}
		}

		m.SetQuestion(fqdn, dns.TypeA)
		r, _, err := dnsClient.Exchange(m, server)

		// 1. 网络层错误处理
		if err != nil {
			// 超时或连接重置。这不代表域名不存在，只能说明当前网络路径不通。
			// 策略：换一个服务器重试。
			continue
		}

		// 2. 协议层响应处理
		if r == nil {
			continue
		}

		switch r.Rcode {
		case dns.RcodeSuccess:
			// RcodeSuccess 意味着域名记录存在（即使 Answer 为空，也代表该 Zone 存在）。
			// 策略：判定为存活，无需再试。
			return false

		case dns.RcodeNameError:
			// NXDOMAIN: 权威服务器明确告知域名不存在。
			// 策略：这是唯一能判死刑的依据。立即返回 true。
			return true

		case dns.RcodeServerFailure, dns.RcodeRefused:
			// SERVFAIL/REFUSED: 目标 DNS 服务器本身出问题或拒绝了我们。
			// 绝对不能因此认为域名无效。
			// 策略：必须重试下一个服务器。
			continue

		default:
			// 其他罕见错误（如 FormatError），保守起见，视为重试或存活。
			continue
		}
	}

	// 循环结束仍未返回，说明所有尝试都失败了（全超时或全拒绝）。
	// 此时我们要问：能确定它死吗？不能。
	// 策略：疑罪从无，保留域名。
	return false
}

// ---------------------- 辅助功能 (下载/解析/IO) ----------------------

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
		// 过滤掉注释行和空行
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

	// 并发控制信号量
	// 为什么要限制下载并发？
	// 防止瞬间发起几十个 HTTP 请求导致带宽占满，引发后续的 DNS 初始化检测超时。
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
	// 扩容 Buffer 以应对某些源文件中可能存在的超长行（虽然罕见，但为了健壮性）
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
	var domain string
	if matches := hostRegex.FindStringSubmatch(line); len(matches) == 2 {
		domain = matches[1]
	} else if matches := domainRegex.FindStringSubmatch(line); len(matches) == 2 {
		domain = matches[1]
	}
	if domain == "" {
		return ""
	}
	// Add reference-inspired validation
	domain = strings.Trim(domain, "./")
	if domain == "localhost" || domain == "local" || !strings.Contains(domain, ".") {
		return ""
	}
	if !validRulePattern.MatchString(domain) {
		return ""
	}
	// For non-wildcard, check strict DNS validity (skip if wildcard for AdBlock compatibility)
	if !strings.Contains(domain, "*") && !isValidDNSDomain(domain) {
		return ""
	}
	return domain
}

// Add these helpers from reference (adjusted for your context)
var validRulePattern = regexp.MustCompile(`^[a-z0-9.\-_*]+$`)

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
