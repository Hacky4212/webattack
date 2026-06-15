package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Client wraps http.Client with security testing features
type Client struct {
	*http.Client
	Config *Config
}

// Config holds HTTP client configuration
type Config struct {
	Timeout        time.Duration
	MaxRetries     int
	Proxy          string
	UserAgent      string
	FollowRedirect bool
	Headers        map[string]string
	Cookies        []*http.Cookie
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Timeout:        15 * time.Second,
		MaxRetries:     2,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		FollowRedirect: true,
		Headers:        make(map[string]string),
	}
}

// NewClient creates a new HTTP client with the given config
func NewClient(cfg *Config) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Set proxy if configured
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		Jar:       jar,
	}

	// Configure redirect behavior
	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Client{
		Client: client,
		Config: cfg,
	}, nil
}

// Request represents an HTTP request with response
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	client  *Client
}

// Response wraps http.Response with additional info
type Response struct {
	*http.Response
	Body       []byte
	Duration   time.Duration
	RequestURL string
}

// NewRequest creates a new request builder
func (c *Client) NewRequest(method, targetURL string) *Request {
	return &Request{
		Method:  method,
		URL:     targetURL,
		Headers: make(map[string]string),
		client:  c,
	}
}

// SetHeader sets a request header
func (r *Request) SetHeader(key, value string) *Request {
	r.Headers[key] = value
	return r
}

// SetBody sets the request body
func (r *Request) SetBody(body string) *Request {
	r.Body = body
	return r
}

// Do executes the request
func (r *Request) Do() (*Response, error) {
	req, err := http.NewRequest(r.Method, r.URL, strings.NewReader(r.Body))
	if err != nil {
		return nil, err
	}

	// Set default headers
	for k, v := range r.client.Config.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", r.client.Config.UserAgent)

	// Set request-specific headers
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}

	// Set cookies
	for _, c := range r.client.Config.Cookies {
		req.AddCookie(c)
	}

	start := time.Now()
	resp, err := r.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}

	// Read body (limit to 10MB)
	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
			if len(body) > 10*1024*1024 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	resp.Body.Close()

	return &Response{
		Response:   resp,
		Body:       body,
		Duration:   duration,
		RequestURL: r.URL,
	}, nil
}

// Get performs a GET request
func (c *Client) Get(targetURL string) (*Response, error) {
	return c.NewRequest("GET", targetURL).Do()
}

// Post performs a POST request
func (c *Client) Post(targetURL, body string) (*Response, error) {
	return c.NewRequest("POST", targetURL).SetBody(body).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").Do()
}

// PostForm performs a POST form request
func (c *Client) PostForm(targetURL string, form url.Values) (*Response, error) {
	return c.NewRequest("POST", targetURL).SetBody(form.Encode()).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").Do()
}

// PostJSON performs a POST JSON request
func (c *Client) PostJSON(targetURL, jsonStr string) (*Response, error) {
	return c.NewRequest("POST", targetURL).SetBody(jsonStr).
		SetHeader("Content-Type", "application/json").Do()
}
