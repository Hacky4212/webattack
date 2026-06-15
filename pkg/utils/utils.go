package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// RandomString generates a random string of given length
func RandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}

// RandomHex generates a random hex string
func RandomHex(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// MD5Hash returns MD5 hash of a string
func MD5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// SHA256Hash returns SHA256 hash of a string
func SHA256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Base64Encode encodes a string to base64
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// Base64Decode decodes a base64 string
func Base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// URLEncode encodes a string for URL
func URLEncode(s string) string {
	return url.QueryEscape(s)
}

// URLDecode decodes a URL-encoded string
func URLDecode(s string) (string, error) {
	return url.QueryUnescape(s)
}

// ExtractURLs extracts URLs from text
func ExtractURLs(text string) []string {
	re := regexp.MustCompile(`https?://[^\s"'<>]+`)
	return re.FindAllString(text, -1)
}

// ExtractForms extracts form names/IDs from HTML
func ExtractForms(html string) []string {
	re := regexp.MustCompile(`<form[^>]*?(?:name|id)=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	forms := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			forms = append(forms, m[1])
		}
	}
	return forms
}

// ExtractInputs extracts input field names from HTML
func ExtractInputs(html string) []string {
	re := regexp.MustCompile(`<input[^>]*?name=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	inputs := make([]string, 0, len(matches))
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			inputs = append(inputs, m[1])
			seen[m[1]] = true
		}
	}
	return inputs
}

// ExtractLinks extracts all <a href> links from HTML
func ExtractLinks(html, baseURL string) []string {
	re := regexp.MustCompile(`<a[^>]*?href=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	links := make([]string, 0, len(matches))
	seen := make(map[string]bool)

	for _, m := range matches {
		if len(m) > 1 {
			link := m[1]
			// Skip javascript: and mailto: links
			if strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "#") {
				continue
			}
			// Make relative URLs absolute
			if !strings.HasPrefix(link, "http") {
				if strings.HasPrefix(link, "//") {
					link = "https:" + link
				} else if strings.HasPrefix(link, "/") {
					link = strings.TrimRight(baseURL, "/") + link
				} else {
					link = strings.TrimRight(baseURL, "/") + "/" + link
				}
			}
			if !seen[link] {
				links = append(links, link)
				seen[link] = true
			}
		}
	}
	return links
}

// ExtractScripts extracts script src URLs from HTML
func ExtractScripts(html, baseURL string) []string {
	re := regexp.MustCompile(`<script[^>]*?src=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	scripts := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			src := m[1]
			if !strings.HasPrefix(src, "http") {
				if strings.HasPrefix(src, "//") {
					src = "https:" + src
				} else if strings.HasPrefix(src, "/") {
					src = strings.TrimRight(baseURL, "/") + src
				} else {
					src = strings.TrimRight(baseURL, "/") + "/" + src
				}
			}
			scripts = append(scripts, src)
		}
	}
	return scripts
}

// ContainsAny checks if string contains any of the given substrings (case-insensitive)
func ContainsAny(s string, substrs []string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// Truncate truncates a string to maxLen
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// FormatDuration formats a duration nicely
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dμs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// ProgressBar returns a simple ASCII progress bar
func ProgressBar(current, total int, width int) string {
	if total == 0 {
		return "[" + strings.Repeat(" ", width) + "] 0%"
	}
	ratio := float64(current) / float64(total)
	filled := int(ratio * float64(width))
	bar := strings.Repeat("=", filled)
	if filled < width {
		bar += ">"
		bar += strings.Repeat(" ", width-filled-1)
	}
	return fmt.Sprintf("[%s] %3.0f%%", bar, ratio*100)
}

// IsValidURL checks if a string is a valid URL
func IsValidURL(rawURL string) bool {
	_, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}

// ParseCookies parses a cookie string into key-value pairs
func ParseCookies(cookieStr string) map[string]string {
	cookies := make(map[string]string)
	pairs := strings.Split(cookieStr, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			cookies[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return cookies
}

// IntMin returns the minimum of two integers
func IntMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IntMax returns the maximum of two integers
func IntMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
