package fuzzer

import (
	"fmt"
	"net/http"
	"net/url"
)

// SQLInjectionFuzzer implements SQL injection testing
type SQLInjectionFuzzer struct {
	targetURL string
	payload   string
}

// NewSQLInjectionFuzzer creates a new SQL injection fuzzer
func NewSQLInjectionFuzzer(targetURL string, payload string) (*SQLInjectionFuzzer, error) {
	if targetURL == "" {
		return nil, fmt.Errorf("target URL cannot be empty")
	}

	// Parse and validate the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	// Ensure URL has a scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	return &SQLInjectionFuzzer{
		targetURL: parsedURL.String(),
		payload:   payload,
	}, nil
}

// Run starts the SQL injection testing process
func (f *SQLInjectionFuzzer) Run() error {
	// Create test URL with SQL injection payload
	testURL := f.targetURL + "?id=" + url.QueryEscape(f.payload)

	// Parse and validate the test URL
	parsedURL, err := url.Parse(testURL)
	if err != nil {
		return fmt.Errorf("invalid test URL: %v", err)
	}

	// Ensure URL has a scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		testURL = parsedURL.String()
	}

	// Send request
	resp, err := http.Get(testURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for SQL errors in response
	if resp.StatusCode == http.StatusInternalServerError {
		return fmt.Errorf("possible SQL injection vulnerability found: server error")
	}

	return nil
}
