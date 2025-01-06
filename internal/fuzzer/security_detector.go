package fuzzer

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// SecurityBlock represents a detected security protection
type SecurityBlock struct {
	Type        string // Type of security protection (e.g., "Cloudflare", "WAF", etc.)
	Description string // Description of what was detected
	Evidence    string // Evidence that led to detection
}

// DetectSecurityProtection checks if a response indicates security protection
func DetectSecurityProtection(resp *http.Response) (*SecurityBlock, error) {
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Reset body for future reads
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	bodyStr := string(body)
	headers := resp.Header

	// Check for Cloudflare
	if isCloudflare(headers, bodyStr) {
		return &SecurityBlock{
			Type:        "Cloudflare",
			Description: "Cloudflare security protection detected",
			Evidence:    getCloudflareEvidence(headers, bodyStr),
		}, nil
	}

	// Check for generic WAF
	if isWAF(headers, bodyStr) {
		return &SecurityBlock{
			Type:        "WAF",
			Description: "Web Application Firewall detected",
			Evidence:    getWAFEvidence(headers, bodyStr),
		}, nil
	}

	// Check for rate limiting
	if isRateLimited(resp.StatusCode, headers, bodyStr) {
		return &SecurityBlock{
			Type:        "Rate Limit",
			Description: "Rate limiting protection detected",
			Evidence:    getRateLimitEvidence(headers, bodyStr),
		}, nil
	}

	// Check for challenge pages
	if isChallengePage(bodyStr) {
		return &SecurityBlock{
			Type:        "Challenge",
			Description: "Security challenge page detected",
			Evidence:    getChallengeEvidence(bodyStr),
		}, nil
	}

	return nil, nil
}

// isCloudflare checks for Cloudflare indicators
func isCloudflare(headers http.Header, body string) bool {
	// Check headers
	if headers.Get("Server") == "cloudflare" ||
		headers.Get("CF-RAY") != "" ||
		headers.Get("cf-cache-status") != "" {
		return true
	}

	// Check body content
	cloudflareIndicators := []string{
		"Checking your browser before accessing",
		"DDoS protection by Cloudflare",
		"Please Wait... | Cloudflare",
		"Please turn JavaScript on and reload the page",
		"security check to access",
	}

	for _, indicator := range cloudflareIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

// isWAF checks for WAF indicators
func isWAF(headers http.Header, body string) bool {
	// Check common WAF headers
	wafHeaders := []string{
		"X-WAF-Protection",
		"X-Security-Headers",
		"X-Protected-By",
		"X-Firewall-Protection",
	}

	for _, header := range wafHeaders {
		if headers.Get(header) != "" {
			return true
		}
	}

	// Check body content
	wafIndicators := []string{
		"blocked by security rules",
		"security violation",
		"access denied",
		"malicious request",
		"suspicious activity",
		"your request has been blocked",
	}

	for _, indicator := range wafIndicators {
		if strings.Contains(strings.ToLower(body), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// isRateLimited checks for rate limiting indicators
func isRateLimited(statusCode int, headers http.Header, body string) bool {
	// Check status code
	if statusCode == 429 {
		return true
	}

	// Check rate limit headers
	rateLimitHeaders := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"Retry-After",
		"X-Rate-Limit-Reset",
	}

	for _, header := range rateLimitHeaders {
		if headers.Get(header) != "" {
			return true
		}
	}

	// Check body content
	rateLimitIndicators := []string{
		"rate limit exceeded",
		"too many requests",
		"please slow down",
		"request limit reached",
	}

	for _, indicator := range rateLimitIndicators {
		if strings.Contains(strings.ToLower(body), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// isChallengePage checks for security challenge pages
func isChallengePage(body string) bool {
	challengeIndicators := []string{
		"verify you are a human",
		"prove you are human",
		"complete security check",
		"captcha",
		"challenge-form",
		"challenge-page",
		"please enable javascript",
		"browser check",
	}

	for _, indicator := range challengeIndicators {
		if strings.Contains(strings.ToLower(body), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// Helper functions to get evidence
func getCloudflareEvidence(headers http.Header, body string) string {
	evidence := []string{}

	if cfRay := headers.Get("CF-RAY"); cfRay != "" {
		evidence = append(evidence, "CF-RAY: "+cfRay)
	}
	if server := headers.Get("Server"); server == "cloudflare" {
		evidence = append(evidence, "Server: cloudflare")
	}
	if strings.Contains(body, "Checking your browser before accessing") {
		evidence = append(evidence, "Challenge page detected")
	}

	return strings.Join(evidence, ", ")
}

func getWAFEvidence(headers http.Header, body string) string {
	evidence := []string{}

	for _, header := range headers {
		if strings.Contains(strings.ToLower(strings.Join(header, " ")), "waf") {
			evidence = append(evidence, "WAF header detected")
			break
		}
	}

	if strings.Contains(strings.ToLower(body), "blocked by security rules") {
		evidence = append(evidence, "Security block message detected")
	}

	return strings.Join(evidence, ", ")
}

func getRateLimitEvidence(headers http.Header, body string) string {
	evidence := []string{}

	if retryAfter := headers.Get("Retry-After"); retryAfter != "" {
		evidence = append(evidence, "Retry-After: "+retryAfter)
	}
	if remaining := headers.Get("X-RateLimit-Remaining"); remaining != "" {
		evidence = append(evidence, "Rate limit remaining: "+remaining)
	}

	// Check body for rate limit messages
	rateLimitMessages := []string{
		"rate limit exceeded",
		"too many requests",
		"please slow down",
		"request limit reached",
	}

	for _, msg := range rateLimitMessages {
		if strings.Contains(strings.ToLower(body), msg) {
			evidence = append(evidence, "Rate limit message: "+msg)
			break
		}
	}

	return strings.Join(evidence, ", ")
}

func getChallengeEvidence(body string) string {
	evidence := []string{}

	if strings.Contains(body, "verify you are a human") {
		evidence = append(evidence, "Human verification required")
	}
	if strings.Contains(body, "captcha") {
		evidence = append(evidence, "CAPTCHA detected")
	}

	return strings.Join(evidence, ", ")
}
