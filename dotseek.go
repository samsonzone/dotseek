package main

import (
	"bytes"
	"embed"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

var (
	apiUser    string
	apiKey     string
	username   string
	clientIP   string
	useSandbox bool

	baseURL              = "https://api.namecheap.com/xml.response"
	maxDomainsPerAPICall = 50
	requestTimeout       = 30 * time.Second
	apiCallDelay         = 5 * time.Millisecond

	cacheFilename       = ".cache.json"
	defaultTldsFilename = "tlds.txt"
	defaultTldURL       = "https://raw.githubusercontent.com/samsonzone/dotseek/refs/heads/main/tlds.txt"
	cacheMaxAgeSeconds  = int64(24 * 60 * 60)

	colorGreen                  = "\033[92m"
	colorRed                    = "\033[91m"
	colorYellow                 = "\033[93m"
	colorReset                  = "\033[0m"
	gTldKeywordsMap             map[string]string
	gSortedTldKeys              []string
	showTLDDescriptions         *bool
	hiddenAvailablePremiumCount int // Counter for available domains hidden due to premium status
)

//go:embed tlds.txt
var embeddedTldFS embed.FS

type TLDData struct {
	TLD      string
	Keywords []string
}

type CachedDomainAttributes struct {
	Domain        string `json:"Domain"`
	Available     string `json:"Available"`
	IsPremiumName string `json:"IsPremiumName"`
}

type CacheEntry struct {
	Timestamp  int64                  `json:"timestamp"`
	Attributes CachedDomainAttributes `json:"attributes"`
}

type ProcessedResult struct {
	DomainName     string
	ColorPrefix    string
	ColorSuffix    string
	PremiumInfo    string
	SourceInfo     string
	IsAvailable    bool
	TLDDescription string
}

// Output structures for different formats
type DomainResult struct {
	Domain      string `json:"domain" yaml:"domain" toml:"domain" xml:"domain"`
	Available   bool   `json:"available" yaml:"available" toml:"available" xml:"available"`
	Premium     bool   `json:"premium" yaml:"premium" toml:"premium" xml:"premium"`
	TLD         string `json:"tld,omitempty" yaml:"tld,omitempty" toml:"tld,omitempty" xml:"tld,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty" toml:"description,omitempty" xml:"description,omitempty"`
}

type OutputData struct {
	XMLName          xml.Name       `xml:"domain_check_results" json:"-" yaml:"-" toml:"-"`
	Timestamp        string         `json:"timestamp" yaml:"timestamp" toml:"timestamp" xml:"timestamp"`
	TotalEvaluated   int            `json:"total_evaluated" yaml:"total_evaluated" toml:"total_evaluated" xml:"total_evaluated"`
	TotalAvailable   int            `json:"total_available" yaml:"total_available" toml:"total_available" xml:"total_available"`
	TotalUnavailable int            `json:"total_unavailable" yaml:"total_unavailable" toml:"total_unavailable" xml:"total_unavailable"`
	TotalPremium     int            `json:"total_premium" yaml:"total_premium" toml:"total_premium" xml:"total_premium"`
	Results          []DomainResult `json:"results" yaml:"results" toml:"results" xml:"results>result"`
}

type NamecheapAPIResponse struct {
	XMLName         xml.Name        `xml:"ApiResponse"`
	Status          string          `xml:"Status,attr"`
	Errors          ErrorsContainer `xml:"Errors"`
	CommandResponse CommandResponse `xml:"CommandResponse"`
}

type ErrorsContainer struct {
	ErrorList []Error `xml:"Error"`
}

type Error struct {
	Number  string `xml:"Number,attr"`
	Message string `xml:",chardata"`
}

type CommandResponse struct {
	Type              string              `xml:"Type,attr"`
	DomainCheckResult []DomainCheckResult `xml:"DomainCheckResult"`
}

type DomainCheckResult struct {
	Domain        string `xml:"Domain,attr"`
	Available     string `xml:"Available,attr"`
	IsPremiumName string `xml:"IsPremiumName,attr"`
}

func loadCache(cacheFilepath string) map[string]CacheEntry {
	cache := make(map[string]CacheEntry)
	if _, err := os.Stat(cacheFilepath); os.IsNotExist(err) {
		return cache
	}
	file, err := os.Open(cacheFilepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not open cache file '%s': %v\n", cacheFilepath, err)
		return cache
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cache); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not decode cache file '%s': %v\n", cacheFilepath, err)
		return make(map[string]CacheEntry)
	}
	return cache
}

func saveCache(cacheFilepath string, cacheData map[string]CacheEntry) {
	file, err := os.OpenFile(cacheFilepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not save cache file '%s': %v\n", cacheFilepath, err)
		return
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cacheData); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not encode cache data to '%s': %v\n", cacheFilepath, err)
	}
}

func isCacheEntryValid(entry CacheEntry, maxAgeSec int64) bool {
	return (time.Now().Unix() - entry.Timestamp) < maxAgeSec
}

func addDomainToCache(cacheData map[string]CacheEntry, domainName string, attributes CachedDomainAttributes) {
	cacheData[domainName] = CacheEntry{
		Timestamp:  time.Now().Unix(),
		Attributes: attributes,
	}
}

func clearCacheFile(cacheFilepath string) {
	if _, err := os.Stat(cacheFilepath); err == nil {
		if err := os.Remove(cacheFilepath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Could not clear cache file '%s': %v\n", cacheFilepath, err)
		} else {
			fmt.Printf("Cache file '%s' cleared.\n", cacheFilepath)
		}
	} else {
		fmt.Printf("Cache file '%s' does not exist. Nothing to clear.\n", cacheFilepath)
	}
}

func loadAndSetEnvVars() {
	godotenv.Load()
	apiUser = os.Getenv("NAMECHEAP_API_USER")
	apiKey = os.Getenv("NAMECHEAP_API_KEY")
	username = os.Getenv("NAMECHEAP_USERNAME")
	clientIP = os.Getenv("NAMECHEAP_CLIENT_IP")
	useSandboxStr := strings.ToLower(os.Getenv("NAMECHEAP_USE_SANDBOX"))
	useSandbox = useSandboxStr == "true"
	if useSandbox {
		baseURL = "https://api.sandbox.namecheap.com/xml.response"
	} else {
		baseURL = "https://api.namecheap.com/xml.response"
	}
}

func validateEnvVars() {
	requiredVars := map[string]string{
		"NAMECHEAP_API_USER":  apiUser,
		"NAMECHEAP_API_KEY":   apiKey,
		"NAMECHEAP_USERNAME":  username,
		"NAMECHEAP_CLIENT_IP": clientIP,
	}
	missingVars := []string{}
	for name, value := range requiredVars {
		if value == "" {
			missingVars = append(missingVars, name)
		}
	}
	if len(missingVars) > 0 {
		fmt.Fprintf(os.Stderr, "Error: Missing required environment variables: %s\n", strings.Join(missingVars, ", "))
		fmt.Fprintln(os.Stderr, "Please set them in your .env file or environment.")
		os.Exit(1)
	}
	fmt.Println("Using Namecheap API")
	if clientIP != "" {
		fmt.Printf("Client IP for API: %s\n\n", clientIP)
	}
}

func readTLDsFromReader(r io.Reader, sourceName string) []TLDData {
	var tldsDataList []TLDData
	if r == nil {
		fmt.Fprintf(os.Stderr, "Warning: No TLD data reader provided for '%s'. No TLDs loaded.\n", sourceName)
		return tldsDataList
	}
	reader := csv.NewReader(r)
	if _, err := reader.Read(); err != nil {
		if err == io.EOF {
			fmt.Fprintf(os.Stderr, "Warning: TLD data from '%s' is empty or contains only a header.\n", sourceName)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Error reading header from TLD data source '%s': %v\n", sourceName, err)
		}
		return tldsDataList
	}
	tldRegex := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	lineNumber := 1
	for {
		lineNumber++
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Error reading TLD data from '%s' on line %d: %v\n", sourceName, lineNumber, err)
			continue
		}
		if len(record) == 0 || strings.TrimSpace(record[0]) == "" || strings.HasPrefix(strings.TrimSpace(record[0]), "#") {
			continue
		}
		tld := strings.ToLower(strings.TrimSpace(record[0]))
		if !tldRegex.MatchString(tld) || strings.Contains(tld, "..") {
			fmt.Fprintf(os.Stderr, "Warning: Invalid TLD format '%s' on line %d from '%s'. Skipping.\n", tld, lineNumber, sourceName)
			continue
		}
		var keywords []string
		if len(record) > 1 && strings.TrimSpace(record[1]) != "" {
			for _, k := range strings.Split(record[1], ",") {
				if tk := strings.ToLower(strings.TrimSpace(k)); tk != "" {
					keywords = append(keywords, tk)
				}
			}
		}
		tldsDataList = append(tldsDataList, TLDData{TLD: tld, Keywords: keywords})
	}
	return tldsDataList
}

func filterTLDsByLength(tldsList []TLDData, lengthFilterStr string) []TLDData {
	if lengthFilterStr == "" {
		return tldsList
	}
	filterRegex := regexp.MustCompile(`^(<=|>=|<|>|=)?(\d+)$`)
	matches := filterRegex.FindStringSubmatch(lengthFilterStr)
	if len(matches) != 3 {
		fmt.Fprintf(os.Stderr, "Error: Invalid TLD length filter format: '%s'.\n", lengthFilterStr)
		os.Exit(1)
	}
	operator := matches[1]
	if operator == "" {
		operator = "="
	}
	value, err := strconv.Atoi(matches[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid number in TLD length filter: '%s'.\n", matches[2])
		os.Exit(1)
	}
	var filtered []TLDData
	for _, item := range tldsList {
		tldLen := len(item.TLD)
		match := false
		switch operator {
		case "<":
			match = tldLen < value
		case ">":
			match = tldLen > value
		case "<=":
			match = tldLen <= value
		case ">=":
			match = tldLen >= value
		case "=":
			match = tldLen == value
		}
		if match {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func filterTLDsByKeywords(tldsList []TLDData, includeKeywords, excludeKeywords []string) []TLDData {
	hasAny := func(itemKeys, query []string) bool {
		for _, q := range query {
			for _, k := range itemKeys {
				if q == k {
					return true
				}
			}
		}
		return false
	}
	var out []TLDData
	for _, item := range tldsList {
		if len(includeKeywords) > 0 && !hasAny(item.Keywords, includeKeywords) {
			continue
		}
		if len(excludeKeywords) > 0 && hasAny(item.Keywords, excludeKeywords) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func buildDomainQueryList(baseInputs []string, tlds []string) ([]string, []string) {
	var explicit, generated []string
	sldRegex := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	for _, raw := range baseInputs {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" {
			continue
		}
		if strings.Contains(d, ".") {
			parts := strings.Split(d, ".")
			valid := len(parts) >= 2
			for _, p := range parts {
				if p == "" {
					valid = false
				}
			}
			if valid {
				explicit = append(explicit, d)
			}
		} else if sldRegex.MatchString(d) {
			for _, t := range tlds {
				generated = append(generated, fmt.Sprintf("%s.%s", d, t))
			}
		}
	}
	sort.Strings(explicit)
	sort.Slice(generated, func(i, j int) bool {
		ti := strings.SplitN(generated[i], ".", 2)[1]
		tj := strings.SplitN(generated[j], ".", 2)[1]
		if ti != tj {
			return ti < tj
		}
		return generated[i] < generated[j]
	})
	return explicit, generated
}

func fetchTLDsFromURL(u string) (io.Reader, error) {
	client := http.Client{Timeout: requestTimeout}
	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TLDs from URL %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d fetching %s", resp.StatusCode, u)
	}
	b, err := io.ReadAll(resp.Body)
	return bytes.NewReader(b), err
}

func checkDomainChunkAvailability(chunk []string) (*NamecheapAPIResponse, error) {
	params := url.Values{}
	params.Add("ApiUser", apiUser)
	params.Add("ApiKey", apiKey)
	params.Add("UserName", username)
	params.Add("ClientIp", clientIP)
	params.Add("Command", "namecheap.domains.check")
	params.Add("DomainList", strings.Join(chunk, ","))
	reqURL := baseURL + "?" + params.Encode()
	client := http.Client{Timeout: requestTimeout}
	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("request failed for %v: %w", chunk, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d for %v: %s", resp.StatusCode, chunk, string(b))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var apiResp NamecheapAPIResponse
	cleaned := bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	if err := xml.Unmarshal(cleaned, &apiResp); err != nil {
		fmt.Fprintf(os.Stderr, "Raw response for %v: %s\n", chunk, string(body))
		return nil, err
	}
	return &apiResp, nil
}

func formatResultForDisplay(
	domain string,
	isAvailable, isPremium, wasExplicit bool,
	showAll, includePremium bool,
	sourceInfo string,
) *ProcessedResult {
	// Apply filtering logic to ALL domains, not just non-explicit ones
	if isPremium && !includePremium {
		if isAvailable {
			hiddenAvailablePremiumCount++
		}
		return nil
	}
	if !isAvailable && !showAll {
		return nil
	}

	prem := ""
	if isPremium {
		prem = " $"
	}
	var pre, suf string
	if isAvailable {
		pre, suf = colorGreen, colorReset
	} else if showAll {
		pre, suf = colorRed, colorReset
	}

	var desc string
	if *showTLDDescriptions {
		for _, t := range gSortedTldKeys {
			if strings.HasSuffix(domain, "."+t) {
				desc = gTldKeywordsMap[t]
				break
			}
		}
	}

	return &ProcessedResult{
		DomainName:     domain,
		ColorPrefix:    pre,
		ColorSuffix:    suf,
		PremiumInfo:    prem,
		SourceInfo:     sourceInfo,
		IsAvailable:    isAvailable,
		TLDDescription: desc,
	}
}

func processAPIResponseChunk(
	apiResp *NamecheapAPIResponse,
	showAll, includePremium bool,
	explicitMap map[string]bool,
	cacheData map[string]CacheEntry,
	useCache bool,
) []ProcessedResult {
	var out []ProcessedResult
	if apiResp == nil {
		fmt.Fprintln(os.Stderr, "Error: nil API response")
		return out
	}
	if len(apiResp.Errors.ErrorList) > 0 {
		for _, e := range apiResp.Errors.ErrorList {
			fmt.Fprintf(os.Stderr, "API Error (%s): %s\n", e.Number, e.Message)
		}
		return out
	}
	for _, r := range apiResp.CommandResponse.DomainCheckResult {
		domain := r.Domain
		avail := r.Available == "true"
		prem := r.IsPremiumName == "true"
		if useCache {
			addDomainToCache(cacheData, domain, CachedDomainAttributes{
				Domain:        domain,
				Available:     r.Available,
				IsPremiumName: r.IsPremiumName,
			})
		}
		wasExp := explicitMap[domain]
		if res := formatResultForDisplay(domain, avail, prem, wasExp, showAll, includePremium, ""); res != nil {
			out = append(out, *res)
		}
	}
	return out
}

func inferFormatFromFilename(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".json":
		return "json"
	case ".xml":
		return "xml"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".csv":
		return "csv"
	default:
		return ""
	}
}

func writeOutputFile(filename, format string, data OutputData) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	switch format {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(data)

	case "xml":
		file.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
		encoder := xml.NewEncoder(file)
		encoder.Indent("", "  ")
		defer encoder.Close()
		return encoder.Encode(data)

	case "yaml":
		encoder := yaml.NewEncoder(file)
		defer encoder.Close()
		return encoder.Encode(data)

	case "toml":
		encoder := toml.NewEncoder(file)
		return encoder.Encode(data)

	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()

		// Write header
		headers := []string{"domain", "available", "premium"}
		if len(data.Results) > 0 && data.Results[0].TLD != "" {
			headers = append(headers, "tld")
		}
		if len(data.Results) > 0 && data.Results[0].Description != "" {
			headers = append(headers, "description")
		}
		if err := writer.Write(headers); err != nil {
			return err
		}

		// Write data
		for _, result := range data.Results {
			record := []string{
				result.Domain,
				strconv.FormatBool(result.Available),
				strconv.FormatBool(result.Premium),
			}
			if len(headers) > 3 {
				record = append(record, result.TLD)
			}
			if len(headers) > 4 {
				record = append(record, result.Description)
			}
			if err := writer.Write(record); err != nil {
				return err
			}
		}

		// Write summary as comment
		writer.Write([]string{
			fmt.Sprintf("# Total evaluated: %d", data.TotalEvaluated),
			fmt.Sprintf("Available: %d", data.TotalAvailable),
			fmt.Sprintf("Unavailable: %d", data.TotalUnavailable),
			fmt.Sprintf("Premium: %d", data.TotalPremium),
		})

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func main() {
	loadAndSetEnvVars()

	domainsArg := flag.String("domains", "", "Comma-separated domains")
	tldLength := flag.String("l", "", "Filter TLDs by length")
	includeKw := flag.String("k", "", "Include keywords")
	excludeKw := flag.String("ek", "", "Exclude keywords")
	includePremium := flag.Bool("p", false, "Include premium")
	showAll := flag.Bool("a", false, "Show all")
	tldFile := flag.String("tld-file", "", "Custom TLD file")
	cliDesc := flag.Bool("tld-descriptions", false, "Show TLD keywords")
	flag.BoolVar(cliDesc, "d", false, "Shorthand for --tld-descriptions")
	noCache := flag.Bool("no-cache", false, "Disable cache")
	clearCacheFlg := flag.Bool("clear-cache", false, "Clear cache")
	cacheAge := flag.Int64("cache-age", cacheMaxAgeSeconds, "Max cache age")
	outputFile := flag.String("output", "", "Output to file (format inferred from extension)")
	flag.StringVar(outputFile, "o", "", "Shorthand for --output")
	outputFormat := flag.String("format", "", "Output format (json|xml|yaml|toml|csv, overrides extension)")
	flag.StringVar(outputFormat, "f", "", "Shorthand for --format")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [opts] <domain>...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nOutput examples:")
		fmt.Fprintln(os.Stderr, "  -o results.json                    # Output to JSON (format inferred)")
		fmt.Fprintln(os.Stderr, "  -o data.csv                        # Output to CSV (format inferred)")
		fmt.Fprintln(os.Stderr, "  -o myfile.txt -f yaml              # Output to YAML (format explicit)")
		fmt.Fprintln(os.Stderr, "  -f json                            # Output to results.json (default name)")
	}
	flag.Parse()
	showTLDDescriptions = cliDesc

	validateEnvVars()
	if *clearCacheFlg {
		clearCacheFile(cacheFilename)
		os.Exit(0)
	}

	var inputs []string
	if *domainsArg != "" {
		for _, d := range strings.Split(*domainsArg, ",") {
			if d = strings.TrimSpace(d); d != "" {
				inputs = append(inputs, d)
			}
		}
	}
	for _, d := range flag.Args() {
		if d = strings.TrimSpace(d); d != "" {
			inputs = append(inputs, d)
		}
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No domains provided")
		flag.Usage()
		os.Exit(1)
	}

	onlyBase := true
	for _, d := range inputs {
		if strings.Contains(d, ".") {
			onlyBase = false
			break
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Printf("\n%sProcess interrupted.%s\n", colorYellow, colorReset)
		os.Exit(130)
	}()

	useCacheRun := !*noCache
	cacheData := make(map[string]CacheEntry)
	if useCacheRun {
		cacheData = loadCache(cacheFilename)
	}

	// Load TLDs
	var tldData []TLDData
	if *tldFile != "" {
		fmt.Printf("Info: Loading TLDs from %s\n", *tldFile)
		f, err := os.Open(*tldFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		tldData = readTLDsFromReader(f, *tldFile)
		f.Close()
	} else {
		fmt.Println("Info: Fetching TLDs from remote.")
		if rdr, err := fetchTLDsFromURL(defaultTldURL); err == nil {
			tldData = readTLDsFromReader(rdr, defaultTldURL)
		} else if f, err2 := os.Open(defaultTldsFilename); err2 == nil {
			fmt.Println("Info: Using local tlds.txt")
			tldData = readTLDsFromReader(f, defaultTldsFilename)
			f.Close()
		} else {
			fmt.Println("Info: Using embedded TLD list")
			e, _ := embeddedTldFS.Open("tlds.txt")
			tldData = readTLDsFromReader(e, "embedded")
			e.Close()
		}
	}
	if len(tldData) == 0 {
		fmt.Fprintln(os.Stderr, "Critical: No TLDs loaded.")
		os.Exit(1)
	}
	gTldKeywordsMap = make(map[string]string)
	for _, it := range tldData {
		gTldKeywordsMap[it.TLD] = strings.Join(it.Keywords, ", ")
		gSortedTldKeys = append(gSortedTldKeys, it.TLD)
	}
	sort.Slice(gSortedTldKeys, func(i, j int) bool {
		return len(gSortedTldKeys[i]) > len(gSortedTldKeys[j])
	})

	if *tldLength != "" {
		tldData = filterTLDsByLength(tldData, *tldLength)
	}
	var incKW, excKW []string
	for _, k := range strings.Split(*includeKw, ",") {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			incKW = append(incKW, k)
		}
	}
	for _, k := range strings.Split(*excludeKw, ",") {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			excKW = append(excKW, k)
		}
	}
	if len(incKW) > 0 || len(excKW) > 0 {
		tldData = filterTLDsByKeywords(tldData, incKW, excKW)
	}

	finalTlds := make([]string, len(tldData))
	for i, it := range tldData {
		finalTlds[i] = it.TLD
	}

	explicit, generated := buildDomainQueryList(inputs, finalTlds)
	all := append(explicit, generated...)
	explicitMap := make(map[string]bool)
	for _, e := range explicit {
		explicitMap[e] = true
	}

	if len(all) == 0 {
		fmt.Println("No domains to check.")
		return
	}

	var results []ProcessedResult
	var toCheck []string
	var totalAvailable, totalUnavailable, totalPremium int

	if useCacheRun {
		fmt.Printf("Evaluating %d domain(s), checking cache...\n", len(all))
		for _, d := range all {
			if ent, ok := cacheData[d]; ok && isCacheEntryValid(ent, *cacheAge) {
				avail := ent.Attributes.Available == "true"
				prem := ent.Attributes.IsPremiumName == "true"
				// patched count
				if avail {
					if prem {
						totalPremium++
					} else {
						totalAvailable++
					}
				} else {
					totalUnavailable++
				}
				if res := formatResultForDisplay(d, avail, prem, explicitMap[d], *showAll, *includePremium, ""); res != nil {
					results = append(results, *res)
				}
			} else {
				toCheck = append(toCheck, d)
			}
		}
		fmt.Printf("%d from cache. %d to check via API.\n", len(results), len(toCheck))
	} else {
		fmt.Printf("Cache disabled. Checking %d domains via API...\n", len(all))
		toCheck = all
	}

	if len(toCheck) > 0 {
		fmt.Printf("Checking %d domain(s) via API...\n", len(toCheck))
		var chunks [][]string
		for i := 0; i < len(toCheck); i += maxDomainsPerAPICall {
			end := i + maxDomainsPerAPICall
			if end > len(toCheck) {
				end = len(toCheck)
			}
			chunks = append(chunks, toCheck[i:end])
		}
		for i, chunk := range chunks {
			if i > 0 && apiCallDelay > 0 {
				time.Sleep(apiCallDelay)
			}
			fmt.Printf("\r  Processing API batch %d of %d...", i+1, len(chunks))
			apiResp, err := checkDomainChunkAvailability(chunk)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nError checking chunk %v: %v\n", chunk, err)
				continue
			}
			if apiResp != nil && len(apiResp.Errors.ErrorList) == 0 {
				for _, r := range apiResp.CommandResponse.DomainCheckResult {
					avail := r.Available == "true"
					prem := r.IsPremiumName == "true"
					// patched count
					if avail {
						if prem {
							totalPremium++
							// fmt.Printf("DEBUG API: Found premium domain: %s (Available:%t, Premium:%t)\n", r.Domain, avail, prem)
						} else {
							totalAvailable++
						}
					} else {
						totalUnavailable++
					}
				}
				chunkRes := processAPIResponseChunk(apiResp, *showAll, *includePremium, explicitMap, cacheData, useCacheRun)
				results = append(results, chunkRes...)
			}
		}
		fmt.Print("\r" + strings.Repeat(" ", 70) + "\r")
		fmt.Println("API checks complete.")
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].IsAvailable != results[j].IsAvailable {
			return results[i].IsAvailable
		}
		return results[i].DomainName < results[j].DomainName
	})

	// Prepare output data if needed
	var outputData OutputData
	needsOutput := *outputFile != "" || *outputFormat != ""

	if needsOutput {
		outputData.Timestamp = time.Now().Format(time.RFC3339)
		outputData.TotalEvaluated = len(all)
		outputData.TotalAvailable = totalAvailable
		outputData.TotalUnavailable = totalUnavailable
		outputData.TotalPremium = totalPremium
	}

	// Display results to console
	fmt.Printf("\n--- Results (%d matching criteria) ---\n", len(results))
	if len(results) == 0 {
		fmt.Println("No domains matched your criteria.")
	} else {
		for _, r := range results {
			if *showTLDDescriptions && r.TLDDescription != "" {
				fmt.Printf("%s%s%s\t\t%s%s\n", r.ColorPrefix, r.DomainName, r.ColorSuffix, r.TLDDescription, r.PremiumInfo)
			} else {
				fmt.Printf("%s%s%s%s\n", r.ColorPrefix, r.DomainName, r.ColorSuffix, r.PremiumInfo)
			}
		}
	}

	if useCacheRun {
		saveCache(cacheFilename, cacheData)
	}

	if hiddenAvailablePremiumCount > 0 {
		fmt.Printf("\n%sNote: %d premium domain(s) available.\nUse -p flag to show%s\n",
			colorYellow, hiddenAvailablePremiumCount, colorReset)
	}
	if useSandbox {
		fmt.Printf("%sNote: Using Namecheap SANDBOX environment.%s\n", colorYellow, colorReset)
	}
	fmt.Printf("\nFinished. Evaluated %d domains total.\n", len(all))

	// fmt.Printf("DEBUG: Total counts - Available:%d, Unavailable:%d, Premium:%d, Hidden Available Premium:%d\n",
	// 	totalAvailable, totalUnavailable, totalPremium, hiddenAvailablePremiumCount)

	if onlyBase && len(all) > 0 {
		fmt.Println("\n--- Summary of All Evaluated Domains ---")
		fmt.Printf("Available:   %s%d%s\n", colorGreen, totalAvailable, colorReset)
		fmt.Printf("Unavailable: %s%d%s\n", colorRed, totalUnavailable, colorReset)
		fmt.Printf("Premium:     %s%d%s\n", colorYellow, totalPremium, colorReset)
	}

	// Write output file if requested
	if needsOutput {
		// Collect all domain results from cache (which now has all the data)
		var allDomainResults []DomainResult

		for _, d := range all {
			var avail, prem bool

			// Check cache for the data
			if ent, ok := cacheData[d]; ok {
				avail = ent.Attributes.Available == "true"
				prem = ent.Attributes.IsPremiumName == "true"
			}

			dr := DomainResult{
				Domain:    d,
				Available: avail,
				Premium:   prem,
			}

			// Extract TLD
			parts := strings.SplitN(d, ".", 2)
			if len(parts) == 2 {
				dr.TLD = parts[1]
			}

			// Get description if enabled
			if *showTLDDescriptions {
				for _, t := range gSortedTldKeys {
					if strings.HasSuffix(d, "."+t) {
						dr.Description = gTldKeywordsMap[t]
						break
					}
				}
			}

			allDomainResults = append(allDomainResults, dr)
		}

		// Sort all results for output
		sort.Slice(allDomainResults, func(i, j int) bool {
			if allDomainResults[i].Available != allDomainResults[j].Available {
				return allDomainResults[i].Available
			}
			return allDomainResults[i].Domain < allDomainResults[j].Domain
		})

		outputData.Results = allDomainResults

		// Determine output filename and format
		outputFilename := *outputFile
		format := *outputFormat

		if format == "" && outputFilename != "" {
			// Try to infer format from filename
			format = inferFormatFromFilename(outputFilename)
			if format == "" {
				fmt.Fprintf(os.Stderr, "\nError: Cannot infer format from filename '%s'. Please specify format with -f flag.\n", outputFilename)
				os.Exit(1)
			}
		} else if format != "" && outputFilename == "" {
			// Use default filename based on format
			outputFilename = "results." + format
		} else if format == "" && outputFilename == "" {
			// This shouldn't happen due to needsOutput check, but just in case
			fmt.Fprintln(os.Stderr, "\nError: No output file or format specified.")
			os.Exit(1)
		}

		// Validate format
		validFormats := map[string]bool{
			"json": true,
			"xml":  true,
			"yaml": true,
			"toml": true,
			"csv":  true,
		}
		if !validFormats[format] {
			fmt.Fprintf(os.Stderr, "\nError: Invalid format '%s'. Valid formats: json, xml, yaml, toml, csv\n", format)
			os.Exit(1)
		}

		// Write the file
		if err := writeOutputFile(outputFilename, format, outputData); err != nil {
			fmt.Fprintf(os.Stderr, "\nError writing output file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nResults written to: %s (format: %s)\n", outputFilename, format)
	}
}
