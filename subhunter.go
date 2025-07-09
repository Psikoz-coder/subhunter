package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

// httpClient is a shared HTTP client for all requests to reuse connections.
var httpClient *http.Client

// init function to initialize package level variables
func init() {
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
		},
	}
}

type Config struct {
	Domain       string
	Output       string
	Verbose      bool
	Check        bool
	CompareFile  string
	Timeout      int
	Threads      int
	UserAgents   []string
}

type CrtResponse struct {
	NameValue string `json:"name_value"`
}

type BufferOverResponse struct {
	FDNSA []string `json:"FDNS_A"`
}

func printBanner() {
	banner := `
   ███████╗██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
   ██╔════╝██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   ███████╗██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ╚════██║██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
   ███████║╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                
                    ` + Cyan + `Advanced Subdomain Enumeration Tool` + Reset + `
                                ` + Yellow + `by: Psikoz` + Reset + `
`
	fmt.Print(banner)
}

func log(config *Config, message string) {
	if config.Verbose {
		fmt.Printf("%s[*]%s %s\n", Blue+Bold, Reset, message)
	}
}

// makeRequest performs an HTTP GET request and returns the body as a string.
func makeRequest(url string, config *Config) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	// Set a random user agent
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(config.UserAgents))))
	userAgent := config.UserAgents[n.Int64()]
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")

	// Create a new HTTP client with timeout from config
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	return string(body), nil
}

// extractSubdomains uses regex to find subdomains in a given text body.
func extractSubdomains(body, domain string) []string {
	re := regexp.MustCompile(`([a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain) + `)`) 
	return re.FindAllString(body, -1)
}

func rapidDNS(domain string, config *Config) []string {
	log(config, "Scanning RapidDNS...")
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1#result", domain)
	resp, err := makeRequest(url, config)
	if err != nil {
		log(config, fmt.Sprintf("RapidDNS error: %v", err))
		return nil
	}
	return extractSubdomains(resp, domain)
}

func riddler(domain string, config *Config) []string {
	log(config, "Scanning Riddler...")
	url := fmt.Sprintf("https://riddler.io/search/exportcsv?q=pld:%s", domain)
	resp, err := makeRequest(url, config)
	if err != nil {
		log(config, fmt.Sprintf("Riddler error: %v", err))
		return nil
	}
	return extractSubdomains(resp, domain)
}

func jldcAnubis(domain string, config *Config) []string {
	log(config, "Scanning JLDC Anubis...")
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	resp, err := makeRequest(url, config)
	if err != nil {
		log(config, fmt.Sprintf("JLDC Anubis error: %v", err))
		return nil
	}
	return extractSubdomains(resp, domain)
}

func crtSh(domain string, config *Config) []string {
	log(config, "Scanning crt.sh...")
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	resp, err := makeRequest(url, config)
	if err != nil {
		log(config, fmt.Sprintf("crt.sh error: %v", err))
		return nil
	}

	var crtData []CrtResponse
	// crt.sh can return a single object on error, so we handle that by ignoring unmarshal errors.
	// The cleanAndFilter function will discard invalid entries anyway.
	_ = json.Unmarshal([]byte(resp), &crtData)

	var result []string
	for _, entry := range crtData {
		nameValue := strings.ReplaceAll(entry.NameValue, "*.", "")
		lines := strings.Split(nameValue, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasSuffix(line, "."+domain) || line == domain {
				result = append(result, line)
			}
		}
	}
	return result
}

func bufferOver(domain string, config *Config) []string {
	log(config, "Scanning BufferOver...")
	url := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain)
	resp, err := makeRequest(url, config)
	if err != nil {
		log(config, fmt.Sprintf("BufferOver error: %v", err))
		return nil
	}

	var bufferData BufferOverResponse
	// Similar to crt.sh, ignore JSON parsing errors for now.
	_ = json.Unmarshal([]byte(resp), &bufferData)

	var result []string
	for _, entry := range bufferData.FDNSA {
		// The entry can be "ip,hostname"
		parts := strings.Split(entry, ",")
		if len(parts) == 2 {
			result = append(result, strings.TrimSpace(parts[1]))
		}
	}
	return result
}

func urlScan(domain string, config *Config) []string {
	log(config, "Scanning URLScan...")
	url := fmt.Sprintf("https://urlscan.io/domain/%s", domain)
	resp, err := makeRequest(url, config)
	if err != nil {
		log(config, fmt.Sprintf("URLScan error: %v", err))
		return nil
	}
	return extractSubdomains(resp, domain)
}

func cleanAndFilter(subdomains []string, domain string) []string {
	unique := make(map[string]bool)
	var result []string

	// Regex to match valid hostnames for the given domain.
	// This is a bit more strict than the original.
	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*` + regexp.QuoteMeta(domain) + `$`)

	for _, sub := range subdomains {
		cleaned := strings.TrimSpace(sub)
		cleaned = strings.ToLower(cleaned)
		cleaned = strings.TrimPrefix(cleaned, "*.")
		cleaned = strings.TrimSuffix(cleaned, ".")

		if domainRegex.MatchString(cleaned) && !unique[cleaned] {
			unique[cleaned] = true
			result = append(result, cleaned)
		}
	}

	sort.Strings(result)
	return result
}

func readSubdomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub != "" {
			subdomains = append(subdomains, sub)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

func compareSubdomains(ours, theirs []string) (onlyOurs, onlyTheirs, common []string) {
	ourSet := make(map[string]bool)
	theirSet := make(map[string]bool)

	for _, sub := range ours {
		ourSet[strings.ToLower(sub)] = true
	}

	for _, sub := range theirs {
		sub = strings.ToLower(sub)
		theirSet[sub] = true
		if ourSet[sub] {
			common = append(common, sub)
		} else {
			onlyTheirs = append(onlyTheirs, sub)
		}
	}

	for _, sub := range ours {
		sub = strings.ToLower(sub)
		if !theirSet[sub] {
			onlyOurs = append(onlyOurs, sub)
		}
	}

	sort.Strings(onlyOurs)
	sort.Strings(onlyTheirs)
	sort.Strings(common)

	return onlyOurs, onlyTheirs, common
}

func writeComparisonResults(ours, theirs, common []string, domain string, config *Config) error {
	timestamp := time.Now().Format("20060102_150405")
	
	// Write comparison results - only create the main output file
	onlyOursFile := config.Output
	summary := fmt.Sprintf(`Subdomain Comparison Summary
==========================
Date: %s
Domain: %s

SubHunter found: %d subdomains
Other tool found: %d subdomains

Unique to SubHunter: %d
Unique to other tool: %d
Common subdomains: %d
`,
		time.Now().Format("2006-01-02 15:04:05"),
		domain,
		len(ours)+len(common),
		len(theirs)+len(common),
		len(ours),
		len(theirs),
		len(common),
	)

	if err := os.WriteFile(summaryFile, []byte(summary), 0644); err != nil {
		return fmt.Errorf("error writing summary: %v", err)
	}

	return nil
}

func writeResults(results []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, result := range results {
		if _, err := writer.WriteString(result + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func checkRequiredTools() error {
	tools := []string{"curl", "wget"}
	var found bool

	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err == nil {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("required tools not found. Please install one of: %v", tools)
	}
	return nil
}

func runCheck() {
	fmt.Printf("%s[+]%s Running system check...\n", Green+Bold, Reset)
	
	// Check required tools
	err := checkRequiredTools()
	if err != nil {
		fmt.Printf("%s[-]%s %v\n", Red+Bold, Reset, err)
	} else {
		fmt.Printf("%s[+]%s All required tools are installed\n", Green+Bold, Reset)
	}

	// Check internet connection
	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{Transport: tr}
	_, err = client.Get("https://www.google.com")
	if err != nil {
		fmt.Printf("%s[-]%s No internet connection: %v\n", Red+Bold, Reset, err)
	} else {
		fmt.Printf("%s[+]%s Internet connection OK\n", Green+Bold, Reset)
	}

	// Check DNS resolution
	_, err = net.LookupHost("google.com")
	if err != nil {
		fmt.Printf("%s[-]%s DNS resolution failed: %v\n", Red+Bold, Reset, err)
	} else {
		fmt.Printf("%s[+]%s DNS resolution OK\n", Green+Bold, Reset)
	}

	fmt.Printf("\n%s[+]%s System check completed!\n", Green+Bold, Reset)
}

func main() {
	var config Config
	var help bool

	// Initialize default configuration
	config.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
	}

	// Define flags
	flag.StringVar(&config.Domain, "d", "", "Target domain")
	flag.StringVar(&config.Domain, "domain", "", "Target domain")
	flag.StringVar(&config.Output, "o", "", "Output file")
	flag.StringVar(&config.Output, "output", "", "Output file")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.Check, "check", false, "Run system check")
	flag.BoolVar(&config.Check, "c", false, "Run system check (shorthand)")
	flag.StringVar(&config.CompareFile, "compare", "", "Compare with subdomains from file")
	flag.IntVar(&config.Timeout, "timeout", 30, "HTTP request timeout in seconds")
	flag.IntVar(&config.Threads, "t", 5, "Number of concurrent threads")
	flag.BoolVar(&help, "h", false, "Show this help message")
	flag.BoolVar(&help, "help", false, "Show this help message")

	// Custom usage message
	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stdout, "\n%sA fast and simple subdomain enumeration tool by Psikoz.%s\n", Cyan, Reset)
		fmt.Fprintf(os.Stdout, "\n%sUsage:%s\n  %s -d <domain> [flags]\n", Yellow, Reset, os.Args[0])
		fmt.Fprintf(os.Stdout, "\n%sRequired Flags:%s\n", Yellow, Reset)
		fmt.Fprintf(os.Stdout, "  -d, --domain string    Target domain to scan\n")
		fmt.Fprintf(os.Stdout, "\n%sOptional Flags:%s\n", Yellow, Reset)
		fmt.Fprintf(os.Stdout, "  -o, --output string    Output file (default: <domain>_<timestamp>.txt)\n")
		fmt.Fprintf(os.Stdout, "  -v, --verbose          Enable verbose output\n")
		fmt.Fprintf(os.Stdout, "  -t, --threads int      Number of concurrent threads (default 5)\n")
		fmt.Fprintf(os.Stdout, "      --timeout int      HTTP request timeout in seconds (default 30)\n")
		fmt.Fprintf(os.Stdout, "  -c, --check            Run system check before scanning\n")
		fmt.Fprintf(os.Stdout, "      --compare string   Compare with subdomains from file\n")
		fmt.Fprintf(os.Stdout, "  -h, --help             Show this help message\n")
		fmt.Fprintf(os.Stdout, "\n%sExamples:%s\n", Yellow, Reset)
		fmt.Fprintf(os.Stdout, "  %s -d example.com -o subs.txt -v\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "  %s -d example.com -t 10 --timeout 60\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "  %s --check\n\n", os.Args[0])
	}

	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
	}

	// Run system check if requested
	if config.Check {
		runCheck()
		os.Exit(0)
	}

	printBanner()

	// Set default output filename if not provided
	if config.Output == "" {
		config.Output = fmt.Sprintf("subhunter_%s.txt", config.Domain)
	}

	// Normalize domain (remove http://, https://, and trailing slashes)
	config.Domain = strings.TrimPrefix(strings.TrimPrefix(config.Domain, "http://"), "https://")
	config.Domain = strings.TrimRight(config.Domain, "/")

	fmt.Printf("%s[+]%s Target:        %s%s%s\n", Green+Bold, Reset, Yellow, config.Domain, Reset)
	fmt.Printf("%s[+]%s Output:        %s%s%s\n", Green+Bold, Reset, Yellow, config.Output, Reset)
	fmt.Printf("%s[+]%s Threads:       %s%d%s\n", Green+Bold, Reset, Yellow, config.Threads, Reset)
	fmt.Printf("%s[+]%s Timeout:       %s%d seconds%s\n", Green+Bold, Reset, Yellow, config.Timeout, Reset)
	fmt.Printf("%s[+]%s Start Time:    %s%s%s\n", Green+Bold, Reset, Yellow, time.Now().Format("2006-01-02 15:04:05"), Reset)
	fmt.Println()
	
	startTime := time.Now()

	sources := []func(string, *Config) []string{
		rapidDNS,
		riddler,
		jldcAnubis,
		crtSh,
		bufferOver,
		urlScan,
	}

	var wg sync.WaitGroup
	resultsChan := make(chan []string, len(sources))

	for _, source := range sources {
		wg.Add(1)
		go func(src func(string, *Config) []string) {
			defer wg.Done()
			resultsChan <- src(config.Domain, &config)
		}(source)
	}

	// This goroutine waits for all workers to finish and then closes the channel.
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var allSubdomains []string
	for results := range resultsChan {
		allSubdomains = append(allSubdomains, results...)
	}

	log(&config, "Merging and cleaning results...")
	cleanResults := cleanAndFilter(allSubdomains, config.Domain)

	// If compare file is provided, compare the results
	if config.CompareFile != "" {
		log(&config, fmt.Sprintf("Comparing with subdomains from: %s", config.CompareFile))
		
		// Read subdomains from the comparison file
		otherSubdomains, err := readSubdomainsFromFile(config.CompareFile)
		if err != nil {
			fmt.Printf("%s[!]%s Error reading comparison file: %v%s\n", Red+Bold, Reset, err, Reset)
			os.Exit(1)
		}

		// Compare the subdomains
		onlyOurs, onlyTheirs, common := compareSubdomains(cleanResults, otherSubdomains)

		// Write comparison results
		if err := writeComparisonResults(onlyOurs, onlyTheirs, common, config.Domain); err != nil {
			fmt.Printf("%s[!]%s Error writing comparison results: %v%s\n", Red+Bold, Reset, err, Reset)
			os.Exit(1)
		}

		// Print comparison summary
		fmt.Printf("\n%s[+]%s Comparison Results:%s\n", Green+Bold, Reset, Reset)
		fmt.Printf("%s[+]%s SubHunter found: %s%d%s subdomains\n", Green+Bold, Reset, Yellow, len(cleanResults), Reset)
		fmt.Printf("%s[+]%s Other tool found: %s%d%s subdomains\n", Green+Bold, Reset, Yellow, len(otherSubdomains), Reset)
		fmt.Printf("%s[+]%s Unique to SubHunter: %s%d%s\n", Green+Bold, Reset, Yellow, len(onlyOurs), Reset)
		fmt.Printf("%s[+]%s Unique to other tool: %s%d%s\n", Green+Bold, Reset, Yellow, len(onlyTheirs), Reset)
		fmt.Printf("%s[+]%s Common subdomains: %s%d%s\n", Green+Bold, Reset, Yellow, len(common), Reset)

		if config.Verbose {
			if len(onlyOurs) > 0 {
				fmt.Printf("\n%s[*]%s Subdomains only found by SubHunter:%s\n", Blue+Bold, Reset, Reset)
				for i, sub := range onlyOurs {
					fmt.Printf("%s%3d%s %s\n", Cyan, i+1, Reset, sub)
				}
			}

			if len(onlyTheirs) > 0 {
				fmt.Printf("\n%s[*]%s Subdomains only found in %s:%s\n", Blue+Bold, Reset, config.CompareFile, Reset)
				for i, sub := range onlyTheirs {
					fmt.Printf("%s%3d%s %s\n", Cyan, i+1, Reset, sub)
				}
			}

			if len(common) > 0 {
				fmt.Printf("\n%s[*]%s Common subdomains:%s\n", Blue+Bold, Reset, Reset)
				for i, sub := range common {
					fmt.Printf("%s%3d%s %s\n", Cyan, i+1, Reset, sub)
				}
			}
		}

		fmt.Printf("\n%s[+]%s Comparison results saved to files with timestamp: %s\n", 
			Green+Bold, Reset, time.Now().Format("20060102_150405"))
	}

	// Write results to file
	if err := writeResults(cleanResults, config.Output); err != nil {
		fmt.Printf("%s[!]%s Error writing results: %v%s\n", Red+Bold, Reset, err, Reset)
		os.Exit(1)
	}

	elapsed := time.Since(startTime)
	fmt.Printf("\n%s[+]%s Scan completed in %s%.2f seconds%s\n", Green+Bold, Reset, Yellow, elapsed.Seconds(), Reset)
	fmt.Printf("%s[+]%s Found %s%d%s unique subdomains\n", Green+Bold, Reset, Yellow, len(cleanResults), Reset)
	fmt.Printf("%s[+]%s Results saved to: %s%s%s\n", Green+Bold, Reset, Yellow, config.Output, Reset)
	
	// Calculate and show the rate
	if elapsed.Seconds() > 0 {
		rate := float64(len(cleanResults)) / elapsed.Seconds()
		fmt.Printf("%s[+]%s Processing rate: %s%.2f subdomains/second%s\n", 
			Green+Bold, Reset, Yellow, rate, Reset)
	}

	if config.Verbose {
		fmt.Printf("\n%s[*]%s Results:%s\n", Blue+Bold, Reset, Reset)
		for i, subdomain := range cleanResults {
			fmt.Printf("%s%3d%s %s\n", Cyan, i+1, Reset, subdomain)
		}
	}
}