package stress

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"webattack/pkg/httpclient"

	"github.com/fatih/color"
	"golang.org/x/time/rate"
)

// Config holds stress test configuration
type Config struct {
	URL         string
	Method      string
	Body        string
	Headers     map[string]string
	ContentType string
	Workers     int
	Duration    time.Duration // 0 = run until MaxRequests reached
	MaxRequests int64         // 0 = run until Duration elapsed
	RateLimit   float64       // requests per second, 0 = no limit
	Timeout     time.Duration
	Verbose     bool
	OutputFile  string
}

// DefaultConfig returns a default stress test configuration
func DefaultConfig() *Config {
	return &Config{
		Method:      "GET",
		Workers:     10,
		Duration:    10 * time.Second,
		MaxRequests: 0,
		RateLimit:   0,
		Headers:     make(map[string]string),
	}
}

// Stats holds cumulative stress test statistics
type Stats struct {
	TotalRequests    int64
	SuccessCount     int64
	FailCount        int64
	BytesTransferred int64

	TotalDuration time.Duration
	MinDuration   time.Duration
	MaxDuration   time.Duration

	StatusCode  map[int]int64
	ErrorCounts map[string]int64 // grouped error messages -> count
	durations   []time.Duration
	durMu       sync.Mutex
	errMu       sync.Mutex
	startTime   time.Time
}

// Tester is the stress test engine
type Tester struct {
	client *httpclient.Client
	config *Config
	stats  *Stats

	stopCh   chan struct{}
	doneCh   chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	rateLim  *rate.Limiter
}

// NewTester creates a new stress tester
func NewTester(client *httpclient.Client, cfg *Config) *Tester {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}

	ctx, cancel := context.WithCancel(context.Background())

	t := &Tester{
		client: client,
		config: cfg,
		stats: &Stats{
			StatusCode:  make(map[int]int64),
			ErrorCounts: make(map[string]int64),
			MinDuration: 1<<63 - 1,
		},
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}

	if cfg.RateLimit > 0 {
		t.rateLim = rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	}

	return t
}

// Run starts the stress test and returns final stats
func (t *Tester) Run() (*Stats, error) {
	t.stats.startTime = time.Now()

	// Print header
	fmt.Printf("\n[*] Starting stress test...\n")
	fmt.Printf("[*] Target:     %s\n", t.config.URL)
	fmt.Printf("[*] Method:     %s\n", t.config.Method)
	fmt.Printf("[*] Workers:    %d\n", t.config.Workers)
	if t.config.Duration > 0 {
		fmt.Printf("[*] Duration:   %v\n", t.config.Duration)
	}
	if t.config.MaxRequests > 0 {
		fmt.Printf("[*] Requests:   %d\n", t.config.MaxRequests)
	}
	if t.config.RateLimit > 0 {
		fmt.Printf("[*] Rate limit: %.0f req/s\n", t.config.RateLimit)
	}
	fmt.Println()

	// Setup deadline if duration is specified
	if t.config.Duration > 0 {
		go func() {
			select {
			case <-time.After(t.config.Duration):
				t.cancel()
			case <-t.ctx.Done():
			}
		}()
	}

	// Setup max requests check
	if t.config.MaxRequests > 0 {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if atomic.LoadInt64(&t.stats.TotalRequests) >= t.config.MaxRequests {
						t.cancel()
						return
					}
				case <-t.ctx.Done():
					return
				}
			}
		}()
	}

	// Progress reporter
	progressDone := make(chan struct{})
	go t.reportProgress(progressDone)

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < t.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.worker()
		}()
	}

	wg.Wait()
	close(progressDone)
	t.stats.TotalDuration = time.Since(t.stats.startTime)

	return t.stats, nil
}

func (t *Tester) worker() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n[!] Worker panic recovered: %v\n", r)
		}
	}()
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Check max requests
		if t.config.MaxRequests > 0 && atomic.LoadInt64(&t.stats.TotalRequests) >= t.config.MaxRequests {
			return
		}

		// Rate limiting
		if t.rateLim != nil {
			t.rateLim.Wait(context.Background())
		}

		t.sendRequest()
	}
}

func (t *Tester) sendRequest() {
	atomic.AddInt64(&t.stats.TotalRequests, 1)

	start := time.Now()

	var resp *httpclient.Response
	var err error

	switch t.config.Method {
	case "GET":
		resp, err = t.client.Get(t.config.URL)
	case "POST":
		if strings.HasPrefix(t.config.ContentType, "application/json") {
			resp, err = t.client.PostJSON(t.config.URL, t.config.Body)
		} else {
			resp, err = t.client.Post(t.config.URL, t.config.Body)
		}
	case "PUT":
		req := t.client.NewRequest("PUT", t.config.URL)
		req.SetBody(t.config.Body)
		if t.config.ContentType != "" {
			req.SetHeader("Content-Type", t.config.ContentType)
		}
		resp, err = req.Do()
	case "DELETE":
		req := t.client.NewRequest("DELETE", t.config.URL)
		resp, err = req.Do()
	case "HEAD":
		req := t.client.NewRequest("HEAD", t.config.URL)
		resp, err = req.Do()
	case "OPTIONS":
		req := t.client.NewRequest("OPTIONS", t.config.URL)
		resp, err = req.Do()
	case "PATCH":
		req := t.client.NewRequest("PATCH", t.config.URL)
		req.SetBody(t.config.Body)
		if t.config.ContentType != "" {
			req.SetHeader("Content-Type", t.config.ContentType)
		}
		resp, err = req.Do()
	default:
		req := t.client.NewRequest(t.config.Method, t.config.URL)
		if t.config.Body != "" {
			req.SetBody(t.config.Body)
		}
		resp, err = req.Do()
	}

	elapsed := time.Since(start)

	if err != nil {
		atomic.AddInt64(&t.stats.FailCount, 1)
		// Track error type for verbose summary
		errKey := summarizeError(err)
		t.stats.errMu.Lock()
		t.stats.ErrorCounts[errKey]++
		t.stats.errMu.Unlock()
		return
	}

	atomic.AddInt64(&t.stats.SuccessCount, 1)
	atomic.AddInt64(&t.stats.BytesTransferred, int64(len(resp.Body)))

	// Track status code
	t.stats.durMu.Lock()
	t.stats.StatusCode[resp.StatusCode]++
	t.stats.durMu.Unlock()

	// Track durations
	t.stats.durMu.Lock()
	t.stats.durations = append(t.stats.durations, elapsed)
	if elapsed < t.stats.MinDuration {
		t.stats.MinDuration = elapsed
	}
	if elapsed > t.stats.MaxDuration {
		t.stats.MaxDuration = elapsed
	}
	t.stats.durMu.Unlock()
}

func (t *Tester) reportProgress(done chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// ANSI escape to clear line from cursor to end
	clearLine := "\033[0K"

	lastLineCount := 0
	lastVerboseTime := time.Now()

	for {
		select {
		case <-done:
			// Move cursor up to clear previous progress lines
			for i := 0; i < lastLineCount; i++ {
				fmt.Print("\033[A" + clearLine)
			}
			fmt.Print("\r" + clearLine)
			return
		case <-ticker.C:
			elapsed := time.Since(t.stats.startTime)
			total := atomic.LoadInt64(&t.stats.TotalRequests)
			success := atomic.LoadInt64(&t.stats.SuccessCount)
			fail := atomic.LoadInt64(&t.stats.FailCount)
			rps := float64(total) / elapsed.Seconds()

			t.stats.durMu.Lock()
			avg := time.Duration(0)
			if len(t.stats.durations) > 0 {
				var sum time.Duration
				for _, d := range t.stats.durations {
					sum += d
				}
				avg = sum / time.Duration(len(t.stats.durations))
			}
			minD := t.stats.MinDuration
			maxD := t.stats.MaxDuration
			t.stats.durMu.Unlock()

			if minD == 1<<63-1 {
				minD = 0
			}

			// Build single-line progress
			line := fmt.Sprintf("    Elapsed: %-8v | Total: %d | Success: %d | Fail: %d | RPS: %.0f | Avg: %v | Min: %v | Max: %v",
				elapsed.Round(time.Second), total, success, fail, rps,
				avg.Round(time.Microsecond), minD.Round(time.Microsecond), maxD.Round(time.Microsecond))

			pct := float64(0)
			if t.config.MaxRequests > 0 {
				pct = float64(total) / float64(t.config.MaxRequests) * 100
				line += fmt.Sprintf(" | %.1f%%", pct)
			}

			t.stats.durMu.Lock()
			if len(t.stats.StatusCode) > 0 {
				parts := make([]string, 0, len(t.stats.StatusCode))
				for code, count := range t.stats.StatusCode {
					parts = append(parts, fmt.Sprintf("%d:%d", code, count))
				}
				line += " | Status: " + strings.Join(parts, " ")
			}
			t.stats.durMu.Unlock()

			// Verbose: print error summary every 10 seconds
			var verboseLines []string
			if t.config.Verbose && fail > 0 && time.Since(lastVerboseTime) >= 10*time.Second {
				lastVerboseTime = time.Now()
				t.stats.errMu.Lock()
				// Show top 3 most frequent errors
				type kv struct {
					Key   string
					Count int64
				}
				var sorted []kv
				for k, v := range t.stats.ErrorCounts {
					sorted = append(sorted, kv{k, v})
				}
				sort.Slice(sorted, func(i, j int) bool { return sorted[i].Count > sorted[j].Count })
				for i, e := range sorted {
					if i >= 3 {
						break
					}
					verboseLines = append(verboseLines, fmt.Sprintf("    [ERR] %s: %d", e.Key, e.Count))
				}
				t.stats.errMu.Unlock()
			}

			// Move up and overwrite previous lines
			for i := 0; i < lastLineCount; i++ {
				fmt.Print("\033[A" + clearLine)
			}
			fmt.Print("\r" + clearLine)
			color.Cyan(line)
			for _, vl := range verboseLines {
				fmt.Print("\n" + clearLine)
				color.Yellow(vl)
			}

			lastLineCount = 1 + len(verboseLines)
		}
	}
}

// PrintReport prints the final stress test report
func (s *Stats) PrintReport() {
	fmt.Println()
	color.Green("╔══════════════════════════════════════════════════════════╗")
	color.Green("║              STRESS TEST COMPLETED                       ║")
	color.Green("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	total := atomic.LoadInt64(&s.TotalRequests)
	success := atomic.LoadInt64(&s.SuccessCount)
	fail := atomic.LoadInt64(&s.FailCount)

	fmt.Printf("  Duration:          %v\n", s.TotalDuration.Round(time.Millisecond))
	fmt.Printf("  Total Requests:    %d\n", total)
	fmt.Printf("  Successful:        %d (%.1f%%)\n", success, float64(success)/float64(total)*100)
	if fail > 0 {
		color.Red("  Failed:            %d (%.1f%%)", fail, float64(fail)/float64(total)*100)
	} else {
		color.Green("  Failed:            %d", fail)
	}

	rps := float64(total) / s.TotalDuration.Seconds()
	fmt.Printf("  Throughput:        %.2f req/s\n", rps)

	bytes := atomic.LoadInt64(&s.BytesTransferred)
	if bytes > 0 {
		mb := float64(bytes) / 1024 / 1024
		fmt.Printf("  Data Transferred:  %.2f MB (%.2f KB/s)\n", mb, float64(bytes)/1024/s.TotalDuration.Seconds())
	}

	fmt.Println()
	fmt.Println("  Response Time:")
	s.durMu.Lock()
	avg := time.Duration(0)
	if len(s.durations) > 0 {
		var sum time.Duration
		for _, d := range s.durations {
			sum += d
		}
		avg = sum / time.Duration(len(s.durations))
	}
	minD := s.MinDuration
	if minD == 1<<63-1 {
		minD = 0
	}
	maxD := s.MaxDuration
	p50 := percentile(s.durations, 50)
	p90 := percentile(s.durations, 90)
	p95 := percentile(s.durations, 95)
	p99 := percentile(s.durations, 99)
	s.durMu.Unlock()

	fmt.Printf("    Min:    %v\n", minD.Round(time.Microsecond))
	fmt.Printf("    Max:    %v\n", maxD.Round(time.Microsecond))
	fmt.Printf("    Avg:    %v\n", avg.Round(time.Microsecond))
	fmt.Printf("    P50:    %v\n", p50.Round(time.Microsecond))
	fmt.Printf("    P90:    %v\n", p90.Round(time.Microsecond))
	fmt.Printf("    P95:    %v\n", p95.Round(time.Microsecond))
	fmt.Printf("    P99:    %v\n", p99.Round(time.Microsecond))

	fmt.Println()
	fmt.Println("  Status Code Distribution:")
	if len(s.StatusCode) == 0 {
		fmt.Println("    (none)")
	} else {
		for code, count := range s.StatusCode {
			pct := float64(count) / float64(total) * 100
			fmt.Printf("    HTTP %d:  %d (%.1f%%)\n", code, count, pct)
		}
	}
	fmt.Println()
}

func percentile(durations []time.Duration, p float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})
	idx := int(math.Ceil(float64(len(durations))*p/100)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(durations) {
		idx = len(durations) - 1
	}
	return durations[idx]
}

// GenerateReport generates a text report string
func (s *Stats) GenerateReport(targetURL string) string {
	var sb strings.Builder

	sb.WriteString("=== Stress Test Report ===\n")
	sb.WriteString(fmt.Sprintf("Target: %s\n", targetURL))
	sb.WriteString(fmt.Sprintf("Duration: %v\n", s.TotalDuration.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("Total Requests: %d\n", atomic.LoadInt64(&s.TotalRequests)))
	sb.WriteString(fmt.Sprintf("Successful: %d\n", atomic.LoadInt64(&s.SuccessCount)))
	sb.WriteString(fmt.Sprintf("Failed: %d\n", atomic.LoadInt64(&s.FailCount)))

	rps := float64(atomic.LoadInt64(&s.TotalRequests)) / s.TotalDuration.Seconds()
	sb.WriteString(fmt.Sprintf("Throughput: %.2f req/s\n", rps))

	sb.WriteString(fmt.Sprintf("Data Transferred: %d bytes\n", atomic.LoadInt64(&s.BytesTransferred)))

	s.durMu.Lock()
	if len(s.durations) > 0 {
		var sum time.Duration
		for _, d := range s.durations {
			sum += d
		}
		avg := sum / time.Duration(len(s.durations))
		sb.WriteString(fmt.Sprintf("Avg Response: %v\n", avg.Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("Min Response: %v\n", s.MinDuration.Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("Max Response: %v\n", s.MaxDuration.Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("P50: %v\n", percentile(s.durations, 50).Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("P95: %v\n", percentile(s.durations, 95).Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("P99: %v\n", percentile(s.durations, 99).Round(time.Microsecond)))
	}
	s.durMu.Unlock()

	sb.WriteString("\nStatus Codes:\n")
	for code, count := range s.StatusCode {
		sb.WriteString(fmt.Sprintf("  %d: %d\n", code, count))
	}

	return sb.String()
}

// summarizeError extracts a short category from an error for grouping
func summarizeError(err error) string {
	msg := err.Error()
	// Common patterns to group by
	switch {
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "connection reset"):
		return "connection reset"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "Timeout"):
		return "timeout"
	case strings.Contains(msg, "no such host") || strings.Contains(msg, "DNS"):
		return "dns error"
	case strings.Contains(msg, "TCP connect"):
		return "tcp connect error"
	case strings.Contains(msg, "TLS"):
		return "tls error"
	case strings.Contains(msg, "EOF"):
		return "unexpected EOF"
	case strings.Contains(msg, "too many open"):
		return "too many open files/sockets"
	default:
		// Truncate long messages to first 60 chars
		if len(msg) > 60 {
			return msg[:60] + "..."
		}
		return msg
	}
}
