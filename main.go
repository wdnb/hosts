package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

// ----------------配置区域----------------

// RuleSource 上游规则源
type RuleSource struct {
	Name    string // 名称
	URL     string // 下载地址
	Enabled bool   // 是否启用
}

// Upstreams 在此配置你要聚合的上游规则（建议先全部打开测试重复率）
var Upstreams = []RuleSource{
	// --- 综合类巨型列表（合并原有 & AdGuard Home 注册中心） ---
	{Name: "HaGeZi Ultimate", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt", Enabled: true},
	{Name: "OISD Big", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt", Enabled: true},
	{Name: "1Hosts Lite", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt", Enabled: true},

	// --- 安全/恶意软件/跟踪（强烈建议保留） ---
	{Name: "Phishing Army", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt", Enabled: true},
	{Name: "Stalkerware", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt", Enabled: true},
	{Name: "Malicious URL Blocklist (URLHaus)", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt", Enabled: true},
	{Name: "Dandelion Sprout's Anti-Malware List", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt", Enabled: true},

	// --- 中文特化（保留原有） ---
	{Name: "217heidai", URL: "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt", Enabled: true},

	// --- 其他特定领域（合并原有 & AdGuard Home 注册中心） ---
	{Name: "NoCoin", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt", Enabled: true},
	{Name: "Perflyst and Dandelion Sprout's Smart-TV Blocklist", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt", Enabled: true},
	{Name: "Dandelion Sprout's Game Console Adblock List", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt", Enabled: true},
	{Name: "HaGeZi's Windows/Office Tracker Blocklist", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt", Enabled: true},
}

const OutputFile = "adblock_aggr_optimized.txt" // 最终输出文件
const CacheDir = "./cache/"                     // 缓存目录

// ----------------核心数据结构----------------

type SourceData struct {
	Name    string
	Domains map[string]struct{}
	Error   error
}

// 缓存元数据（支持 ETag、Last-Modified 和缓存时间）
type CacheMetadata struct {
	ETag         string    `json:"etag"`
	LastModified string    `json:"last_modified"`
	FetchedAt    time.Time `json:"fetched_at"` // 缓存时间，用于强制过期
}

const CacheMetaFile = ".meta" // 元数据文件后缀

// 域名合法性正则（严格符合 RFC 规范）
var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$`)

func main() {
	start := time.Now()
	fmt.Println("开始并行下载与聚合规则...")

	if err := os.MkdirAll(CacheDir, 0755); err != nil {
		fmt.Printf("创建缓存目录失败: %v\n", err)
		return
	}

	results := fetchAll(Upstreams)

	// 全局去重
	globalSet := make(map[string]struct{})
	for _, res := range results {
		if res.Error != nil {
			continue
		}
		for domain := range res.Domains {
			globalSet[domain] = struct{}{}
		}
	}

	// 重复率分析
	analyzeRedundancy(results, globalSet)

	// 写入最终文件
	fmt.Printf("\n正在写入最终规则文件 %s（共 %d 条）...\n", OutputFile, len(globalSet))
	if err := writeToFileAtomic(globalSet, results); err != nil {
		fmt.Printf("写入失败: %v\n", err)
	} else {
		fmt.Printf("完成！总耗时：%v\n", time.Since(start))
	}
}

// ----------------重复率分析----------------
func analyzeRedundancy(results []SourceData, globalSet map[string]struct{}) {
	fmt.Println("\n规则重合度与贡献度分析报告")
	fmt.Println(strings.Repeat("=", 90))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "源名称\t总规则数\t独有规则数\t重复率\t备注")
	fmt.Fprintln(w, "----\t----\t----\t----\t----")

	failed := 0
	for _, cur := range results {

		if cur.Error != nil {
			if strings.Contains(cur.Error.Error(), "禁用") {
				fmt.Fprintf(w, "%s\t已禁用\t-\t-\t\n", cur.Name)
			} else {
				fmt.Fprintf(w, "%s\t下载失败\t-\t-\t\n", cur.Name)
			}
			failed++
			continue
		}

		// 其他源的联合集
		others := make(map[string]struct{})
		for _, other := range results {
			if other.Name == cur.Name || other.Error != nil {
				continue
			}
			for d := range other.Domains {
				others[d] = struct{}{}
			}
		}

		unique := 0
		for d := range cur.Domains {
			if _, ok := others[d]; !ok {
				unique++
			}
		}

		total := len(cur.Domains)
		repeatRate := 0.0
		if total > 0 {
			repeatRate = 100.0 * float64(total-unique) / float64(total)
		}

		hint := ""
		if repeatRate > 95 {
			hint = "高度冗余，可考虑关闭"
		} else if repeatRate > 80 {
			hint = "重复较多"
		}

		fmt.Fprintf(w, "%s\t%d\t%d\t%.2f%%\t%s\n", cur.Name, total, unique, repeatRate, hint)
	}
	w.Flush()

	if failed > 0 {
		fmt.Printf("\n注意：有 %d 个源下载失败，分析结果可能不完整\n", failed)
	}
	fmt.Println(strings.Repeat("=", 90))
	fmt.Println("提示：独有规则越少，说明该源越可以被其他源替代")
}

// ----------------并发下载（带缓存 + 重试 + 过期）----------------
func fetchAll(sources []RuleSource) []SourceData {
	var wg sync.WaitGroup
	results := make([]SourceData, len(sources))

	for i, src := range sources {
		if !src.Enabled {
			results[i] = SourceData{Name: src.Name, Error: fmt.Errorf("已禁用")}
			continue
		}

		wg.Add(1)
		go func(idx int, s RuleSource) {
			defer wg.Done()
			domains, err := fetchWithCacheAndRetry(s)
			results[idx] = SourceData{Name: s.Name, Domains: domains, Error: err}

			if err != nil {
				fmt.Printf("[%s] 下载失败: %v\n", s.Name, err)
			} else {
				fmt.Printf("[%s] 完成，解析出 %d 条规则\n", s.Name, len(domains))
			}
		}(i, src)
	}
	wg.Wait()
	return results
}

// 核心下载函数：支持缓存、304、24小时强制过期、3次重试
func fetchWithCacheAndRetry(src RuleSource) (map[string]struct{}, error) {
	cacheFile := CacheDir + strings.ReplaceAll(src.Name, " ", "_") + ".txt"
	metaFile := CacheDir + strings.ReplaceAll(src.Name, " ", "_") + CacheMetaFile

	// 读取元数据
	var meta CacheMetadata
	if data, err := os.ReadFile(metaFile); err == nil {
		if json.Unmarshal(data, &meta) != nil {
			meta = CacheMetadata{} // 元数据损坏则忽略
		}
	}

	// 如果缓存不到24小时且文件存在，可直接使用（跳过请求）
	if !meta.FetchedAt.IsZero() && time.Since(meta.FetchedAt) < 24*time.Hour {
		if _, err := os.Stat(cacheFile); err == nil {
			fmt.Printf("[%s] 使用近期缓存（%v前）\n", src.Name, time.Since(meta.FetchedAt).Round(time.Minute))
			return parseFromFile(cacheFile)
		}
	}

	// 带重试的下载
	var resp *http.Response
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err = doConditionalRequest(src.URL, meta)
		if err == nil {
			break
		}
		if attempt < 3 {
			time.Sleep(time.Second * time.Duration(attempt))
		}
	}

	if err != nil {
		// 所有重试失败，尝试用旧缓存
		if _, statErr := os.Stat(cacheFile); statErr == nil {
			fmt.Printf("[%s] 下载失败，使用旧缓存\n", src.Name)
			return parseFromFile(cacheFile)
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		fmt.Printf("[%s] 未更新（304），使用缓存\n", src.Name)
		return parseFromFile(cacheFile)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// 更新缓存与元数据
	if err := saveResponseToCache(resp, cacheFile, metaFile); err != nil {
		return nil, err
	}
	return parseFromFile(cacheFile)
}

func doConditionalRequest(url string, meta CacheMetadata) (*http.Response, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}
	if meta.LastModified != "" {
		req.Header.Set("If-Modified-Since", meta.LastModified)
	}
	return client.Do(req)
}

func saveResponseToCache(resp *http.Response, cacheFile, metaFile string) error {
	// 保存新内容
	f, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}

	// 更新元数据
	newMeta := CacheMetadata{
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		FetchedAt:    time.Now(),
	}
	data, _ := json.MarshalIndent(newMeta, "", "  ")
	return os.WriteFile(metaFile, data, 0644)
}

// ----------------解析规则----------------
func parseFromFile(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, _ := f.Stat()
	if info.Size() > 200*1024*1024 { // 限制 200MB 防止爆内存
		return nil, fmt.Errorf("文件过大：%s", path)
	}

	domains := make(map[string]struct{}, 500_000) // 预分配容量
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024) // 最大行长 10MB

	for scanner.Scan() {
		if domain := extractDomain(scanner.Text()); domain != "" {
			domains[domain] = struct{}{}
		}
	}
	return domains, scanner.Err()
}

// 提取域名，仅保留纯域名规则（严格模式）
func extractDomain(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
		return ""
	}

	// 去除行尾注释
	if i := strings.IndexAny(line, "#!"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}

	// 已经是 AdGuard 格式 ||domain^
	if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
		domain := strings.TrimPrefix(line, "||")
		domain = strings.TrimSuffix(domain, "^")
		if domainRegex.MatchString(domain) {
			return strings.ToLower(domain)
		}
		return ""
	}

	// hosts 格式
	if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			line = parts[1]
		}
	}

	// 去除 	 常见修饰符
	line = strings.TrimPrefix(line, "||")
	if i := strings.Index(line, "^"); i >= 0 {
		line = line[:i]
	}
	if strings.ContainsAny(line, "/:*[]") { // 复杂规则直接丢弃
		return ""
	}

	domain := strings.ToLower(strings.TrimSpace(line))
	if domainRegex.MatchString(domain) {
		return domain
	}
	return ""
}

// ----------------原子写入最终文件----------------
func writeToFileAtomic(domains map[string]struct{}, sources []SourceData) error {
	tmpFile := OutputFile + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	// Header
	fmt.Fprintln(w, "!")
	fmt.Fprintln(w, "! Title: 优化聚合广告拦截列表")
	fmt.Fprintf(w, "! 更新时间: %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "! 总规则数: %d\n", len(domains))
	fmt.Fprintln(w, "! 来源:")
	for _, s := range sources {
		if s.Error == nil {
			fmt.Fprintf(w, "!   - %s\n", s.Name)
		}
	}
	fmt.Fprintln(w, "!")

	// 排序输出
	list := make([]string, 0, len(domains))
	for d := range domains {
		list = append(list, d)
	}
	sort.Strings(list)

	for _, d := range list {
		fmt.Fprintf(w, "||%s^\n", d)
	}

	if err := w.Flush(); err != nil {
		os.Remove(tmpFile)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return err
	}
	return os.Rename(tmpFile, OutputFile)
}
