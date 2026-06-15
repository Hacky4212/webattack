package scanner

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

// VulnType represents a vulnerability type
type VulnType string

const (
	VulnOpenDir      VulnType = "open-directory"
	VulnExposedFile  VulnType = "exposed-file"
	VulnInfoLeak     VulnType = "info-leak"
	VulnHeaderIssue  VulnType = "header-issue"
	VulnMethodAllow  VulnType = "method-allowed"
	VulnOutdatedTech VulnType = "outdated-technology"
	VulnWeakCookie   VulnType = "weak-cookie"
	VulnCORS         VulnType = "cors-misconfig"
	VulnClickjacking VulnType = "clickjacking"
)

// Finding represents a vulnerability finding
type Finding struct {
	URL        string
	Type       VulnType
	Severity   string
	Title      string
	Detail     string
	Evidence   string
	Remediation string
}

// Scanner is the main web vulnerability scanner
type Scanner struct {
	client    *httpclient.Client
	baseURL   string
	results   []Finding
	mu        sync.Mutex
	verbose   bool
	scannedURLs map[string]bool
}

// NewScanner creates a new web vulnerability scanner
func NewScanner(client *httpclient.Client, verbose bool) *Scanner {
	return &Scanner{
		client:      client,
		verbose:     verbose,
		scannedURLs: make(map[string]bool),
	}
}

// Scan performs a comprehensive scan
func (s *Scanner) Scan(targetURL string) ([]Finding, error) {
	s.baseURL = strings.TrimRight(targetURL, "/")
	s.results = nil

	fmt.Printf("\n[*] Starting web vulnerability scan on: %s\n", targetURL)
	fmt.Printf("[*] Time: %s\n\n", time.Now().Format(time.RFC3339))

	// Phase 1: Basic information gathering
	fmt.Printf("[1/8] Gathering server information...\n")
	s.gatherInfo(targetURL)

	// Phase 2: Directory/file discovery
	fmt.Printf("[2/8] Scanning for exposed directories and files...\n")
	s.scanDirectories()

	// Phase 3: Security headers check
	fmt.Printf("[3/8] Checking security headers...\n")
	s.checkSecurityHeaders()

	// Phase 4: Cookie security check
	fmt.Printf("[4/8] Checking cookie security...\n")
	s.checkCookieSecurity()

	// Phase 5: HTTP methods check
	fmt.Printf("[5/8] Testing HTTP methods...\n")
	s.checkHTTPMethods()

	// Phase 6: CORS configuration check
	fmt.Printf("[6/8] Checking CORS configuration...\n")
	s.checkCORSMisconfig()

	// Phase 7: Information leakage check
	fmt.Printf("[7/8] Checking information leakage...\n")
	s.checkInfoLeakage()

	// Phase 8: Technology fingerprinting
	fmt.Printf("[8/8] Fingerprinting technologies...\n")
	s.fingerprintTechnologies()

	return s.results, nil
}

// gatherInfo gathers basic server information
func (s *Scanner) gatherInfo(targetURL string) {
	resp, err := s.client.Get(targetURL)
	if err != nil {
		s.addFinding(Finding{
			URL:      targetURL,
			Type:     VulnInfoLeak,
			Severity: "info",
			Title:    "Connection failed",
			Detail:   fmt.Sprintf("Failed to connect: %v", err),
		})
		return
	}

	// Check server header
	server := resp.Header.Get("Server")
	if server != "" {
		fmt.Printf("    Server: %s\n", server)
		// Check for outdated servers
		serverLower := strings.ToLower(server)
		if strings.Contains(serverLower, "apache/2.2") ||
			strings.Contains(serverLower, "apache/2.0") ||
			strings.Contains(serverLower, "iis/6") ||
			strings.Contains(serverLower, "iis/5") ||
			strings.Contains(serverLower, "nginx/0") ||
			strings.Contains(serverLower, "tomcat/4") ||
			strings.Contains(serverLower, "tomcat/5") ||
			strings.Contains(serverLower, "tomcat/6") {
			s.addFinding(Finding{
				URL:         targetURL,
				Type:        VulnOutdatedTech,
				Severity:    "medium",
				Title:       "Outdated Server Version",
				Detail:      fmt.Sprintf("Server version exposed: %s", server),
				Remediation: "Update to the latest stable version and hide the Server header",
			})
		}
	}

	// Check X-Powered-By header
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		fmt.Printf("    X-Powered-By: %s\n", poweredBy)
		s.addFinding(Finding{
			URL:         targetURL,
			Type:        VulnInfoLeak,
			Severity:    "low",
			Title:       "Technology Disclosure via X-Powered-By",
			Detail:      fmt.Sprintf("X-Powered-By header reveals: %s", poweredBy),
			Evidence:    fmt.Sprintf("Header: X-Powered-By: %s", poweredBy),
			Remediation: "Remove or suppress the X-Powered-By header",
		})
	}

	fmt.Printf("    Status: %d, Size: %d bytes\n", resp.StatusCode, len(resp.Body))
}

// scanDirectories discovers common directories and files
func (s *Scanner) scanDirectories() {
	total := len(payloads.CommonDirectories) + len(payloads.CommonFiles)
	checked := 0

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	check := func(path string) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		targetURL := s.baseURL + "/" + path
		resp, err := s.client.Get(targetURL)
		if err != nil {
			return
		}

		if resp.StatusCode == 200 {
			statusMsg := fmt.Sprintf("    [FOUND] /%s (Status: %d, Size: %d)", path, resp.StatusCode, len(resp.Body))
			fmt.Println(statusMsg)

			severity := "low"
			detail := fmt.Sprintf("Accessible path: /%s", path)

			// Elevate severity for sensitive paths
			sensitivePaths := []string{".git", ".svn", ".env", "backup", "config", "db", "sql"}
			if utils.ContainsAny(path, sensitivePaths) {
				severity = "high"
				detail = fmt.Sprintf("Sensitive path accessible: /%s - may contain credentials or source code", path)
			}

			s.addFinding(Finding{
				URL:         targetURL,
				Type:        VulnExposedFile,
				Severity:    severity,
				Title:       fmt.Sprintf("Exposed: /%s", path),
				Detail:      detail,
				Evidence:    fmt.Sprintf("HTTP %d, Response size: %d bytes", resp.StatusCode, len(resp.Body)),
				Remediation: "Restrict access to this path or remove it",
			})
		} else if resp.StatusCode == 403 {
			if s.verbose {
				fmt.Printf("    [DENIED] /%s (403 Forbidden)\n", path)
			}
		}
	}

	for _, dir := range payloads.CommonDirectories {
		wg.Add(1)
		checked++
		go check(dir)

		if checked%10 == 0 {
			fmt.Printf("\r    Progress: %s", utils.ProgressBar(checked, total, 30))
		}
	}

	for _, file := range payloads.CommonFiles {
		wg.Add(1)
		checked++
		go check(file)
	}

	wg.Wait()
	fmt.Printf("\r    Progress: %s\n", utils.ProgressBar(total, total, 30))
	fmt.Printf("    Scanned %d paths\n", total)
}

// checkSecurityHeaders checks for security-related HTTP headers
func (s *Scanner) checkSecurityHeaders() {
	resp, err := s.client.Get(s.baseURL)
	if err != nil {
		return
	}

	headersToCheck := map[string]string{
		"Strict-Transport-Security":    "HSTS not enabled - MITM attacks possible",
		"Content-Security-Policy":      "CSP not set - XSS and data injection risks",
		"X-Content-Type-Options":       "Missing X-Content-Type-Options - MIME sniffing possible",
		"X-Frame-Options":              "Missing X-Frame-Options - clickjacking possible",
		"X-XSS-Protection":            "Missing X-XSS-Protection header",
		"Referrer-Policy":             "Missing Referrer-Policy - info leakage possible",
		"Permissions-Policy":          "Missing Permissions-Policy header",
		"Cross-Origin-Resource-Policy": "Missing CORP header",
	}

	missingCount := 0
	for header, description := range headersToCheck {
		value := resp.Header.Get(header)
		if value == "" {
			missingCount++
			if s.verbose {
				fmt.Printf("    [MISSING] %s\n", header)
			}

			severity := "low"
			if header == "Content-Security-Policy" || header == "Strict-Transport-Security" {
				severity = "medium"
			}

			s.addFinding(Finding{
				URL:         s.baseURL,
				Type:        VulnHeaderIssue,
				Severity:    severity,
				Title:       fmt.Sprintf("Missing Security Header: %s", header),
				Detail:      description,
				Evidence:    fmt.Sprintf("Header '%s' not found in response", header),
				Remediation: fmt.Sprintf("Add the '%s' header with appropriate values", header),
			})
		}
	}

	fmt.Printf("    %d/%d security headers missing\n", missingCount, len(headersToCheck))
}

// checkCookieSecurity checks cookie attributes
func (s *Scanner) checkCookieSecurity() {
	resp, err := s.client.Get(s.baseURL)
	if err != nil {
		return
	}

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		if s.verbose {
			fmt.Println("    No cookies set")
		}
		return
	}

	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)

		issues := []string{}

		if !strings.Contains(cookieLower, "secure") {
			issues = append(issues, "Missing Secure flag")
		}
		if !strings.Contains(cookieLower, "httponly") {
			issues = append(issues, "Missing HttpOnly flag")
		}
		if !strings.Contains(cookieLower, "samesite") {
			issues = append(issues, "Missing SameSite attribute")
		}

		if len(issues) > 0 {
			fmt.Printf("    [WEAK] %s\n", utils.Truncate(cookie, 80))
			s.addFinding(Finding{
				URL:         s.baseURL,
				Type:        VulnWeakCookie,
				Severity:    "medium",
				Title:       "Weak Cookie Configuration",
				Detail:      strings.Join(issues, "; "),
				Evidence:    cookie,
				Remediation: "Set Secure, HttpOnly, and SameSite=Lax/Strict on all cookies",
			})
		}
	}
}

// checkHTTPMethods tests allowed HTTP methods
func (s *Scanner) checkHTTPMethods() {
	for _, method := range payloads.HTTPMethods {
		req := s.client.NewRequest(method, s.baseURL)
		resp, err := req.Do()
		if err != nil {
			continue
		}

		if resp.StatusCode != 405 && resp.StatusCode != 501 {
			if method == "PUT" || method == "DELETE" {
				s.addFinding(Finding{
					URL:         s.baseURL,
					Type:        VulnMethodAllow,
					Severity:    "medium",
					Title:       fmt.Sprintf("Dangerous HTTP Method Allowed: %s", method),
					Detail:      fmt.Sprintf("HTTP %s method is allowed (Status: %d)", method, resp.StatusCode),
					Evidence:    fmt.Sprintf("Response: %d %s", resp.StatusCode, resp.Status),
					Remediation: fmt.Sprintf("Disable the %s method if not required", method),
				})
				fmt.Printf("    [WARNING] %s method allowed (Status: %d)\n", method, resp.StatusCode)
			} else if method == "TRACE" {
				s.addFinding(Finding{
					URL:         s.baseURL,
					Type:        VulnMethodAllow,
					Severity:    "high",
					Title:       "HTTP TRACE Method Enabled",
					Detail:      "TRACE method can be used for Cross-Site Tracing (XST) attacks",
					Evidence:    fmt.Sprintf("Response: %d", resp.StatusCode),
					Remediation: "Disable the TRACE method",
				})
				fmt.Printf("    [DANGER] TRACE method enabled!\n")
			}

			if s.verbose {
				fmt.Printf("    [ALLOWED] %s (Status: %d)\n", method, resp.StatusCode)
			}
		}
	}
}

// checkCORSMisconfig checks for CORS misconfiguration
func (s *Scanner) checkCORSMisconfig() {
	req := s.client.NewRequest("GET", s.baseURL)
	req.SetHeader("Origin", "https://evil.com")
	resp, err := req.Do()
	if err != nil {
		return
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "*" && acac == "true" {
		s.addFinding(Finding{
			URL:         s.baseURL,
			Type:        VulnCORS,
			Severity:    "high",
			Title:       "Dangerous CORS Configuration",
			Detail:      "ACAO: * with ACAC: true - allows any origin with credentials",
			Evidence:    fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
			Remediation: "Do not use wildcard ACAO with credentials",
		})
		fmt.Printf("    [DANGER] CORS misconfiguration: ACAO=*, ACAC=true\n")
	} else if acao == "*" {
		s.addFinding(Finding{
			URL:         s.baseURL,
			Type:        VulnCORS,
			Severity:    "low",
			Title:       "Wildcard CORS Origin",
			Detail:      "Access-Control-Allow-Origin is set to *",
			Evidence:    fmt.Sprintf("ACAO: %s", acao),
			Remediation: "Restrict CORS to specific trusted origins",
		})
		fmt.Printf("    [INFO] CORS wildcard origin (*) detected\n")
	} else if acao == "https://evil.com" {
		s.addFinding(Finding{
			URL:         s.baseURL,
			Type:        VulnCORS,
			Severity:    "high",
			Title:       "CORS Origin Reflection",
			Detail:      "Server reflects arbitrary Origin header values",
			Evidence:    fmt.Sprintf("Request Origin: https://evil.com, Response ACAO: %s", acao),
			Remediation: "Validate Origin against a whitelist instead of reflecting it",
		})
		fmt.Printf("    [DANGER] CORS origin reflection detected!\n")
	}
}

// checkInfoLeakage checks for information leakage
func (s *Scanner) checkInfoLeakage() {
	// Check common info leak paths
	leakPaths := []struct {
		path string
		desc string
	}{
		{"/.git/HEAD", "Git repository exposed"},
		{"/.svn/entries", "SVN repository exposed"},
		{"/.env", "Environment file exposed"},
		{"/.DS_Store", "macOS metadata file exposed"},
		{"/phpinfo.php", "PHP info page exposed"},
		{"/server-status", "Apache server status exposed"},
		{"/server-info", "Apache server info exposed"},
		{"/wp-config.php.bak", "WordPress config backup exposed"},
		{"/crossdomain.xml", "Cross-domain policy (check for wildcard)"},
		{"/web.config", "IIS web config exposed"},
		{"/WEB-INF/web.xml", "Java web.xml exposed"},
		{"/actuator/health", "Spring Boot actuator exposed"},
		{"/actuator/env", "Spring Boot environment exposed"},
		{"/.vscode/sftp.json", "VS Code SFTP config exposed"},
		{"/package.json", "Node.js package.json exposed"},
		{"/composer.json", "PHP composer.json exposed"},
	}

	for _, leak := range leakPaths {
		targetURL := s.baseURL + leak.path
		resp, err := s.client.Get(targetURL)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			fmt.Printf("    [LEAK] %s - %s\n", leak.path, leak.desc)
			s.addFinding(Finding{
				URL:         targetURL,
				Type:        VulnInfoLeak,
				Severity:    "high",
				Title:       leak.desc,
				Detail:      fmt.Sprintf("Path accessible: %s", leak.path),
				Evidence:    fmt.Sprintf("HTTP %d, Size: %d bytes", resp.StatusCode, len(resp.Body)),
				Remediation: "Restrict access to this path immediately",
			})
		}
	}
}

// fingerprintTechnologies identifies technologies used by the target
func (s *Scanner) fingerprintTechnologies() {
	resp, err := s.client.Get(s.baseURL)
	if err != nil {
		return
	}

	body := strings.ToLower(string(resp.Body))
	headers := fmt.Sprintf("%v", strings.ToLower(fmt.Sprintf("%v", resp.Header)))

	techSignatures := map[string]string{
		"jQuery":       "jquery",
		"Bootstrap":    "bootstrap",
		"React":        "react",
		"Angular":      "angular|ng-version",
		"Vue.js":       "vue",
		"WordPress":    "wp-content|wp-includes",
		"Drupal":       "drupal",
		"Joomla":       "joomla",
		"Laravel":      "laravel",
		"Django":       "django|csrftoken",
		"Ruby on Rails": "rails",
		"ASP.NET":      "asp.net|__viewstate",
		"PHP":          "php",
		"nginx":        "nginx",
		"Apache":       "apache",
		"IIS":          "iis|microsoft-iis",
		"Cloudflare":   "cloudflare",
		"AWS":          "aws|amazon",
		"Google Cloud": "cloud.google",
		"Font Awesome": "font-awesome|fontawesome",
	}

	detected := []string{}
	for tech, sig := range techSignatures {
		for _, pattern := range strings.Split(sig, "|") {
			if strings.Contains(body, pattern) || strings.Contains(headers, pattern) {
				detected = append(detected, tech)
				break
			}
		}
	}

	if len(detected) > 0 {
		fmt.Printf("    Detected: %s\n", strings.Join(detected, ", "))
	}
}

func (s *Scanner) addFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, f)
}

// PrintResults prints scan results
func PrintResults(results []Finding) {
	if len(results) == 0 {
		color.Green("\n[+] No vulnerabilities found. Target appears secure.")
		return
	}

	// Count by severity
	high, medium, low, info := 0, 0, 0, 0
	for _, r := range results {
		switch r.Severity {
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		default:
			info++
		}
	}

	fmt.Printf("\n")
	color.Cyan("╔══════════════════════════════════════════════════════════╗")
	color.Cyan("║           WEB VULNERABILITY SCAN RESULTS                ║")
	color.Cyan("╚══════════════════════════════════════════════════════════╝\n")

	fmt.Printf("  High: %d | Medium: %d | Low: %d | Info: %d\n\n", high, medium, low, info)

	for i, r := range results {
		fmt.Printf("[%d] ", i+1)
		sevColor := color.RedString
		switch r.Severity {
		case "high":
			sevColor = color.RedString
		case "medium":
			sevColor = color.YellowString
		case "low":
			sevColor = color.GreenString
		default:
			sevColor = color.BlueString
		}

		fmt.Printf("%s | %s\n", sevColor(strings.ToUpper(r.Severity)), r.Title)
		fmt.Printf("    URL:      %s\n", r.URL)
		fmt.Printf("    Detail:   %s\n", r.Detail)
		if r.Remediation != "" {
			fmt.Printf("    Fix:      %s\n", r.Remediation)
		}
		fmt.Println()
	}
}

// Report generates a text report
func Report(results []Finding, targetURL string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Web Vulnerability Scan Report\n"))
	sb.WriteString(fmt.Sprintf("==============================\n"))
	sb.WriteString(fmt.Sprintf("Target: %s\n", targetURL))
	sb.WriteString(fmt.Sprintf("Date:   %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Total Findings: %d\n\n", len(results)))

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("[%d] %s - %s\n", i+1, strings.ToUpper(r.Severity), r.Title))
		sb.WriteString(fmt.Sprintf("    Type:     %s\n", r.Type))
		sb.WriteString(fmt.Sprintf("    URL:      %s\n", r.URL))
		sb.WriteString(fmt.Sprintf("    Detail:   %s\n", r.Detail))
		sb.WriteString(fmt.Sprintf("    Evidence: %s\n", r.Evidence))
		sb.WriteString(fmt.Sprintf("    Fix:      %s\n\n", r.Remediation))
	}
	return sb.String()
}

// Ensure url is used
var _ = url.Parse
