// Copyright 2025 Brian Samson <brian@samson.zone>
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

	"github.com/joho/godotenv"
)

var (
	apiUser    string
	apiKey     string
	username   string
	clientIP   string
	useSandbox bool

	baseURL              string
	maxDomainsPerAPICall = 50
	requestTimeout       = 30 * time.Second
	apiCallDelay         = 5 * time.Millisecond

	cacheFilename       = ".cache.json"
	defaultTldsFilename = "tlds.txt"
	defaultTldURL       = "https://raw.githubusercontent.com/samsonzone/freedot-cli/refs/heads/main/ref/tlds.txt"
	cacheMaxAgeSeconds  = int64(24 * 60 * 60)

	colorGreen          = "\033[92m"
	colorRed            = "\033[91m"
	colorYellow         = "\033[93m"
	colorReset          = "\033[0m"
	gTldKeywordsMap     map[string]string
	gSortedTldKeys      []string
	showTLDDescriptions *bool
)

//go:embed tlds.txt
var embeddedTldsContent []byte
var _ embed.FS

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
		if sourceName == "embedded tlds.txt" && len(embeddedTldsContent) == 0 {
			fmt.Fprintf(os.Stderr, "Error: Embedded TLD list is empty or uninitialized.\n")
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
			rawKeywords := strings.Split(record[1], ",")
			for _, k := range rawKeywords {
				trimmedK := strings.ToLower(strings.TrimSpace(k))
				if trimmedK != "" {
					keywords = append(keywords, trimmedK)
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
	var filteredList []TLDData
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
		default:
			fmt.Fprintf(os.Stderr, "Error: Unknown operator in TLD length filter: '%s'.\n", operator)
			os.Exit(1)
		}
		if match {
			filteredList = append(filteredList, item)
		}
	}
	return filteredList
}

func filterTLDsByKeywords(tldsList []TLDData, includeKeywords, excludeKeywords []string) []TLDData {
	hasAnyKeyword := func(tldAssociatedKeywords, queryKeywords []string) bool {
		if len(queryKeywords) == 0 {
			return false
		}
		for _, qk := range queryKeywords {
			for _, tk := range tldAssociatedKeywords {
				if qk == tk {
					return true
				}
			}
		}
		return false
	}
	var filteredList []TLDData
	for _, item := range tldsList {
		if len(includeKeywords) > 0 && !hasAnyKeyword(item.Keywords, includeKeywords) {
			continue
		}
		if len(excludeKeywords) > 0 && hasAnyKeyword(item.Keywords, excludeKeywords) {
			continue
		}
		filteredList = append(filteredList, item)
	}
	return filteredList
}

func buildDomainQueryList(baseDomainsInput []string, processedTLDs []string) ([]string, []string) {
	var explicitDomains, generatedDomains []string
	sldRegex := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	for _, rawDomainInput := range baseDomainsInput {
		cleanDomain := strings.ToLower(strings.TrimSpace(rawDomainInput))
		if cleanDomain == "" {
			continue
		}
		if strings.Contains(cleanDomain, ".") {
			parts := strings.Split(cleanDomain, ".")
			validFQDN := true
			if len(parts) < 2 {
				validFQDN = false
			}
			for _, part := range parts {
				if part == "" {
					validFQDN = false
					break
				}
			}
			if validFQDN {
				explicitDomains = append(explicitDomains, cleanDomain)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Skipping malformed explicit domain '%s'.\n", cleanDomain)
			}
		} else {
			if sldRegex.MatchString(cleanDomain) {
				for _, tld := range processedTLDs {
					generatedDomains = append(generatedDomains, fmt.Sprintf("%s.%s", cleanDomain, tld))
				}
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Skipping malformed base domain '%s' for TLD generation.\n", cleanDomain)
			}
		}
	}
	sort.Slice(generatedDomains, func(i, j int) bool {
		partsI := strings.SplitN(generatedDomains[i], ".", 2)
		tldI := ""
		if len(partsI) > 1 {
			tldI = partsI[1]
		}
		partsJ := strings.SplitN(generatedDomains[j], ".", 2)
		tldJ := ""
		if len(partsJ) > 1 {
			tldJ = partsJ[1]
		}
		if tldI != tldJ {
			return tldI < tldJ
		}
		return generatedDomains[i] < generatedDomains[j]
	})
	sort.Strings(explicitDomains)
	return explicitDomains, generatedDomains
}

func fetchTLDsFromURL(urlStr string) (io.Reader, error) {
	client := http.Client{Timeout: requestTimeout}
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TLDs from URL %s: %w", urlStr, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to fetch TLDs from URL %s: status code %d", urlStr, resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read TLD response body from URL %s: %w", urlStr, err)
	}
	return bytes.NewReader(bodyBytes), nil
}

func checkDomainChunkAvailability(domainChunk []string) (*NamecheapAPIResponse, error) {
	params := url.Values{}
	params.Add("ApiUser", apiUser)
	params.Add("ApiKey", apiKey)
	params.Add("UserName", username)
	params.Add("ClientIp", clientIP)
	params.Add("Command", "namecheap.domains.check")
	params.Add("DomainList", strings.Join(domainChunk, ","))
	reqURL := baseURL + "?" + params.Encode()
	client := http.Client{Timeout: requestTimeout}
	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("request failed for domains %v: %w", domainChunk, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP Error: %d for domains %v. Response: %s", resp.StatusCode, domainChunk, string(bodyBytes))
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for %v: %w", domainChunk, err)
	}
	var apiResponse NamecheapAPIResponse
	cleanedBody := bytes.TrimPrefix(bodyBytes, []byte("\xef\xbb\xbf"))
	if err := xml.Unmarshal(cleanedBody, &apiResponse); err != nil {
		fmt.Fprintf(os.Stderr, "Raw response for problematic chunk (%v): %s\n", domainChunk, string(bodyBytes))
		return nil, fmt.Errorf("failed to parse XML response for %v: %w", domainChunk, err)
	}
	return &apiResponse, nil
}

func formatResultForDisplay(
	domainName string,
	isAvailableFlag bool,
	isPremium bool,
	wasExplicitlyRequested bool,
	showAllGenerated bool,
	includePremiumGenerated bool,
	sourceInfo string,
) *ProcessedResult {
	if !wasExplicitlyRequested {
		if !showAllGenerated && !isAvailableFlag {
			return nil
		}
		if isPremium && !includePremiumGenerated {
			return nil
		}
	}
	premiumText := ""
	if isPremium {
		premiumText = " $"
	}
	var cPrefix, cSuffix string
	if isAvailableFlag {
		cPrefix = colorGreen
		cSuffix = colorReset
	} else {
		if showAllGenerated || wasExplicitlyRequested {
			cPrefix = colorRed
			cSuffix = colorReset
		}
	}

	var tldDescText string
	if *showTLDDescriptions {
		var matchedTld string
		for _, knownTld := range gSortedTldKeys {
			if strings.HasSuffix(domainName, "."+knownTld) {
				matchedTld = knownTld
				break
			} else if domainName == knownTld {
				matchedTld = knownTld
				break
			}
		}
		if matchedTld != "" {
			if desc, ok := gTldKeywordsMap[matchedTld]; ok {
				tldDescText = desc
			}
		}
	}

	return &ProcessedResult{
		DomainName:     domainName,
		ColorPrefix:    cPrefix,
		ColorSuffix:    cSuffix,
		PremiumInfo:    premiumText,
		SourceInfo:     sourceInfo,
		IsAvailable:    isAvailableFlag,
		TLDDescription: tldDescText,
	}
}

func processAPIResponseChunk(
	apiResp *NamecheapAPIResponse,
	showAllGenerated bool,
	includePremiumGenerated bool,
	explicitlyRequestedDomainsMap map[string]bool,
	cacheData map[string]CacheEntry,
	useCache bool,
) []ProcessedResult {
	var processedResultsForChunk []ProcessedResult
	if apiResp == nil {
		fmt.Fprintln(os.Stderr, "Error: processAPIResponseChunk called with nil API response.")
		return processedResultsForChunk
	}
	if len(apiResp.Errors.ErrorList) > 0 {
		for _, apiErr := range apiResp.Errors.ErrorList {
			fmt.Fprintf(os.Stderr, "API Error (%s): %s\n", apiErr.Number, apiErr.Message)
		}
		return processedResultsForChunk
	}
	if len(apiResp.CommandResponse.DomainCheckResult) == 0 && len(apiResp.Errors.ErrorList) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: No DomainCheckResult elements in API response for '%s'. Status: %s.\n",
			apiResp.CommandResponse.Type, apiResp.Status)
		return processedResultsForChunk
	}
	for _, resultElement := range apiResp.CommandResponse.DomainCheckResult {
		domain := resultElement.Domain
		isAvailable := resultElement.Available == "true"
		isPremium := resultElement.IsPremiumName == "true"
		if useCache {
			addDomainToCache(cacheData, domain, CachedDomainAttributes{
				Domain: domain, Available: resultElement.Available, IsPremiumName: resultElement.IsPremiumName,
			})
		}
		wasExplicitlyRequested := explicitlyRequestedDomainsMap[domain]
		formatted := formatResultForDisplay(
			domain, isAvailable, isPremium, wasExplicitlyRequested,
			showAllGenerated, includePremiumGenerated, "",
		)
		if formatted != nil {
			processedResultsForChunk = append(processedResultsForChunk, *formatted)
		}
	}
	return processedResultsForChunk
}

func main() {
	loadAndSetEnvVars()
	domainsArg := flag.String("domains", "", "Comma-separated domain names (base or FQDN).")
	tldLengthFilter := flag.String("l", "", "Filter TLDs by length (e.g., '3', '<4', '>=5').")
	keywordsIncludeStr := flag.String("k", "", "Comma-separated keywords to include TLDs by.")
	keywordsExcludeStr := flag.String("ek", "", "Comma-separated keywords to exclude TLDs by.")
	includePremium := flag.Bool("p", false, "Include premium domains in results for generated names.")
	showAll := flag.Bool("a", false, "Show all generated domains (available and unavailable).")
	tldFileFlag := flag.String("tld-file", "", fmt.Sprintf("Path to TLD file (overrides remote/default '%s').", defaultTldsFilename))
	cliShowTLDDescriptions := flag.Bool("tld-descriptions", false, "Show TLD keywords (descriptions).")
	flag.BoolVar(cliShowTLDDescriptions, "d", false, "Show TLD keywords (shorthand for --tld-descriptions)")
	noCache := flag.Bool("no-cache", false, "Disable cache for this run.")
	clearCache := flag.Bool("clear-cache", false, "Clear cache file and exit.")
	cacheAge := flag.Int64("cache-age", cacheMaxAgeSeconds, "Max cache age in seconds.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <domain1> [domain2 ...]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(os.Stderr, "Checks domain availability via Namecheap API with caching.")
		fmt.Fprintln(os.Stderr, "Domains can be provided as arguments or via the -domains flag (comma-separated).")
		fmt.Fprintln(os.Stderr, "\nTLD List Loading Order (if --tld-file is NOT used):")
		fmt.Fprintf(os.Stderr, "  1. Remote URL: %s\n  2. Local file in CWD: %s\n  3. Embedded TLD list\n", defaultTldURL, defaultTldsFilename)
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nRequired Environment Variables (or .env file):")
		fmt.Fprintln(os.Stderr, "  NAMECHEAP_API_USER, NAMECHEAP_API_KEY, NAMECHEAP_USERNAME, NAMECHEAP_CLIENT_IP")
		fmt.Fprintln(os.Stderr, "  NAMECHEAP_USE_SANDBOX (optional, 'true' for sandbox)")
	}
	flag.Parse()
	showTLDDescriptions = cliShowTLDDescriptions

	validateEnvVars()

	if *clearCache {
		clearCacheFile(cacheFilename)
		os.Exit(0)
	}

	var domainInputs []string
	if *domainsArg != "" {
		for _, d := range strings.Split(*domainsArg, ",") {
			if trimmed := strings.TrimSpace(d); trimmed != "" {
				domainInputs = append(domainInputs, trimmed)
			}
		}
	}
	for _, argDomain := range flag.Args() {
		if trimmed := strings.TrimSpace(argDomain); trimmed != "" {
			domainInputs = append(domainInputs, trimmed)
		}
	}

	if len(domainInputs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No domains provided.")
		flag.Usage()
		os.Exit(1)
	}

	onlyBaseDomainsProvided := true
	for _, input := range domainInputs {
		if strings.Contains(input, ".") {
			onlyBaseDomainsProvided = false
			break
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n%sProcess interrupted.%s\n", colorYellow, colorReset)
		os.Exit(130)
	}()

	useCacheThisRun := !*noCache
	currentCacheData := make(map[string]CacheEntry)
	if useCacheThisRun {
		currentCacheData = loadCache(cacheFilename)
	}

	var tldsDataList []TLDData
	explicitTldFile := *tldFileFlag
	if explicitTldFile != "" {
		fmt.Printf("Info: Loading TLDs from specified file: %s\n", explicitTldFile)
		file, err := os.Open(explicitTldFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening specified TLD file '%s': %v\n", explicitTldFile, err)
			os.Exit(1)
		}
		tldsDataList = readTLDsFromReader(file, explicitTldFile)
		file.Close()
	} else {
		fmt.Printf("Info: Fetching TLDs from remote.\n")
		remoteReader, err := fetchTLDsFromURL(defaultTldURL)
		if err == nil {
			tldsDataList = readTLDsFromReader(remoteReader, defaultTldURL)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Failed to fetch TLDs from remote (%s): %v\n", defaultTldURL, err)
			fmt.Printf("Info: Attempting local TLD file: %s\n", defaultTldsFilename)
			file, localErr := os.Open(defaultTldsFilename)
			if localErr == nil {
				fmt.Printf("Info: Using local TLD file: %s\n", defaultTldsFilename)
				tldsDataList = readTLDsFromReader(file, defaultTldsFilename)
				file.Close()
			} else {
				if !os.IsNotExist(localErr) {
					fmt.Fprintf(os.Stderr, "Warning: Error opening local TLD file '%s': %v\n", defaultTldsFilename, localErr)
				}
				fmt.Println("Info: Using embedded TLD list as fallback.")
				if len(embeddedTldsContent) == 0 {
					fmt.Fprintln(os.Stderr, "Critical: Embedded TLD list is empty.")
					os.Exit(1)
				}
				tldsDataList = readTLDsFromReader(bytes.NewReader(embeddedTldsContent), "embedded tlds.txt")
			}
		}
	}
	if len(tldsDataList) == 0 {
		fmt.Fprintln(os.Stderr, "Critical: No TLDs loaded.")
		os.Exit(1)
	}

	gTldKeywordsMap = make(map[string]string)
	tempSortedKeys := make([]string, 0, len(tldsDataList))
	for _, item := range tldsDataList {
		gTldKeywordsMap[item.TLD] = strings.Join(item.Keywords, ", ")
		tempSortedKeys = append(tempSortedKeys, item.TLD)
	}
	sort.Slice(tempSortedKeys, func(i, j int) bool {
		return len(tempSortedKeys[i]) > len(tempSortedKeys[j])
	})
	gSortedTldKeys = tempSortedKeys

	if *tldLengthFilter != "" {
		tldsDataList = filterTLDsByLength(tldsDataList, *tldLengthFilter)
	}
	var includeKw, excludeKw []string
	if *keywordsIncludeStr != "" {
		for _, k := range strings.Split(*keywordsIncludeStr, ",") {
			if tk := strings.ToLower(strings.TrimSpace(k)); tk != "" {
				includeKw = append(includeKw, tk)
			}
		}
	}
	if *keywordsExcludeStr != "" {
		for _, k := range strings.Split(*keywordsExcludeStr, ",") {
			if tk := strings.ToLower(strings.TrimSpace(k)); tk != "" {
				excludeKw = append(excludeKw, tk)
			}
		}
	}

	var filteredTldsForGeneration []TLDData = tldsDataList
	if len(includeKw) > 0 || len(excludeKw) > 0 {
		filteredTldsForGeneration = filterTLDsByKeywords(filteredTldsForGeneration, includeKw, excludeKw)
	}
	finalTLDList := make([]string, len(filteredTldsForGeneration))
	for i, item := range filteredTldsForGeneration {
		finalTLDList[i] = item.TLD
	}

	explicitDomains, generatedDomains := buildDomainQueryList(domainInputs, finalTLDList)
	allDomainsToEvaluate := append(explicitDomains, generatedDomains...)
	explicitlyRequestedDomainsMap := make(map[string]bool)
	for _, d := range explicitDomains {
		explicitlyRequestedDomainsMap[d] = true
	}

	if len(allDomainsToEvaluate) == 0 {
		fmt.Println("No domains to check. Exiting.")
		os.Exit(0)
	}

	var allResultsForDisplay []ProcessedResult
	var domainsNeedingAPICheck []string
	var availableCount, unavailableCount, premiumCount int

	if useCacheThisRun {
		fmt.Printf("Evaluating %d domain(s), checking cache...\n", len(allDomainsToEvaluate))
		for _, domainName := range allDomainsToEvaluate {
			if entry, found := currentCacheData[domainName]; found && isCacheEntryValid(entry, *cacheAge) {
				attrs := entry.Attributes
				isAvailable := attrs.Available == "true"
				isPremium := attrs.IsPremiumName == "true"

				if isAvailable {
					availableCount++
				} else {
					unavailableCount++
				}
				if isPremium {
					premiumCount++
				}

				formatted := formatResultForDisplay(domainName, isAvailable, isPremium,
					explicitlyRequestedDomainsMap[domainName], *showAll, *includePremium, "")
				if formatted != nil {
					allResultsForDisplay = append(allResultsForDisplay, *formatted)
				}
			} else {
				domainsNeedingAPICheck = append(domainsNeedingAPICheck, domainName)
			}
		}
		fmt.Printf("%d from cache. %d to check via API.\n", len(allResultsForDisplay), len(domainsNeedingAPICheck))
	} else {
		fmt.Printf("Cache disabled. Evaluating %d domain(s) via API...\n", len(allDomainsToEvaluate))
		domainsNeedingAPICheck = allDomainsToEvaluate
	}

	if len(domainsNeedingAPICheck) > 0 {
		fmt.Printf("Checking %d domain(s) via API...\n", len(domainsNeedingAPICheck))
		var domainChunks [][]string
		for i := 0; i < len(domainsNeedingAPICheck); i += maxDomainsPerAPICall {
			end := i + maxDomainsPerAPICall
			if end > len(domainsNeedingAPICheck) {
				end = len(domainsNeedingAPICheck)
			}
			domainChunks = append(domainChunks, domainsNeedingAPICheck[i:end])
		}
		for i, chunk := range domainChunks {
			if i > 0 && apiCallDelay > 0 {
				time.Sleep(apiCallDelay)
			}
			fmt.Printf("\r  Processing API batch %d of %d...", i+1, len(domainChunks))
			apiResp, err := checkDomainChunkAvailability(chunk)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nError checking chunk %v: %v\n", chunk, err)
				continue
			}
			if apiResp != nil {
				if len(apiResp.Errors.ErrorList) == 0 {
					for _, result := range apiResp.CommandResponse.DomainCheckResult {
						if result.Available == "true" {
							availableCount++
						} else {
							unavailableCount++
						}
						if result.IsPremiumName == "true" {
							premiumCount++
						}
					}
				}

				chunkResults := processAPIResponseChunk(apiResp, *showAll, *includePremium,
					explicitlyRequestedDomainsMap, currentCacheData, useCacheThisRun)
				allResultsForDisplay = append(allResultsForDisplay, chunkResults...)
			}
		}
		fmt.Print("\r" + strings.Repeat(" ", 70) + "\r")
		fmt.Println("API checks complete.")
	}

	sort.Slice(allResultsForDisplay, func(i, j int) bool {
		resI, resJ := allResultsForDisplay[i], allResultsForDisplay[j]
		if resI.IsAvailable != resJ.IsAvailable {
			return !resI.IsAvailable
		}
		return resI.DomainName < resJ.DomainName
	})

	fmt.Printf("\n--- Results (%d matching criteria) ---\n", len(allResultsForDisplay))
	if len(allResultsForDisplay) == 0 {
		fmt.Println("No domains matched your criteria.")
	} else {
		for _, res := range allResultsForDisplay {
			if *showTLDDescriptions && res.TLDDescription != "" {
				fmt.Printf("%s%s%s\t\t%s%s\n",
					res.ColorPrefix, res.DomainName, res.ColorSuffix,
					res.TLDDescription,
					res.PremiumInfo)
			} else {
				fmt.Printf("%s%s%s%s\n",
					res.ColorPrefix, res.DomainName, res.ColorSuffix, res.PremiumInfo)
			}
		}
	}

	if useCacheThisRun {
		saveCache(cacheFilename, currentCacheData)
	}
	if useSandbox {
		fmt.Printf("%sNote: Using Namecheap SANDBOX environment.%s\n", colorYellow, colorReset)
	}
	fmt.Printf("\nFinished. Evaluated %d domains total.\n", len(allDomainsToEvaluate))

	if onlyBaseDomainsProvided && len(allDomainsToEvaluate) > 0 {
		fmt.Println("\n--- Summary of All Evaluated Domains ---")
		fmt.Printf("Available:   %s%d%s\n", colorGreen, availableCount, colorReset)
		fmt.Printf("Unavailable: %s%d%s\n", colorRed, unavailableCount, colorReset)
		fmt.Printf("Premium:     %s%d%s\n", colorYellow, premiumCount, colorReset)
	}
}
