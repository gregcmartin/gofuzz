package fuzzer

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"fuzzer/internal/html"
)

// CoverageFuzzer implements coverage-guided fuzzing for web applications
type CoverageFuzzer struct {
	// Base configuration
	config *Config

	// HTML form parser
	form *html.Form

	// Coverage tracking
	coverage *Coverage

	// Grammar for generating inputs
	grammar map[string][]string

	// HTTP client
	client *http.Client

	// Interesting inputs that led to new coverage
	corpus []string

	// Protect concurrent access
	mu sync.RWMutex
}

// NewCoverageFuzzer creates a new coverage-guided fuzzer
func NewCoverageFuzzer(config *Config) (*CoverageFuzzer, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Get initial page and parse form
	resp, err := client.Get(config.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get target URL: %v", err)
	}
	defer resp.Body.Close()

	// Parse HTML form
	form, err := html.ParseForm(string(readBody(resp)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse form: %v", err)
	}

	// Generate grammar from form
	grammar := form.GenerateGrammar()

	fuzzer := &CoverageFuzzer{
		config:   config,
		form:     form,
		coverage: NewCoverage(),
		grammar:  grammar,
		client:   client,
		corpus:   make([]string, 0),
	}

	return fuzzer, nil
}

// Run starts the fuzzing process
func (f *CoverageFuzzer) Run() error {
	// Create worker pool
	var wg sync.WaitGroup
	results := make(chan *Result, f.config.Concurrency)

	// Start workers
	for i := 0; i < f.config.Concurrency; i++ {
		wg.Add(1)
		go f.worker(&wg, results)
	}

	// Start result processor
	go f.processResults(results)

	// Wait for all workers to complete
	wg.Wait()
	close(results)

	return nil
}

// worker performs the actual fuzzing
func (f *CoverageFuzzer) worker(wg *sync.WaitGroup, results chan<- *Result) {
	defer wg.Done()

	requestsPerWorker := f.config.NumRequests / f.config.Concurrency

	for i := 0; i < requestsPerWorker; i++ {
		// Generate input
		input := f.generateInput()

		// Test the input
		result := f.testInput(input)
		results <- result

		// If we found new coverage, add to corpus
		if f.coverage.HasNewCoverage(input) {
			f.mu.Lock()
			f.corpus = append(f.corpus, input)
			f.mu.Unlock()
		}
	}
}

// generateInput creates a new test input
func (f *CoverageFuzzer) generateInput() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// 70% chance to mutate from corpus if available
	if len(f.corpus) > 0 && randFloat() < 0.7 {
		base := f.corpus[randInt(len(f.corpus))]
		return f.mutateInput(base)
	}

	// Otherwise generate new input from grammar
	return f.generateFromGrammar()
}

// mutateInput modifies an existing input
func (f *CoverageFuzzer) mutateInput(input string) string {
	parsedURL, err := url.Parse(input)
	if err != nil {
		return f.generateFromGrammar()
	}

	query := parsedURL.Query()

	// Pick a random mutation strategy
	switch randInt(4) {
	case 0: // Change parameter value
		if len(query) > 0 {
			param := randomKey(query)
			query.Set(param, f.generateParamValue(param))
		}
	case 1: // Add new parameter
		params := f.form.Fields
		if len(params) > 0 {
			param := randomMapKey(params)
			query.Set(param, f.generateParamValue(param))
		}
	case 2: // Remove parameter
		if len(query) > 0 {
			param := randomKey(query)
			query.Del(param)
		}
	case 3: // Duplicate parameter
		if len(query) > 0 {
			param := randomKey(query)
			query.Add(param, f.generateParamValue(param))
		}
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// generateFromGrammar creates input from the grammar
func (f *CoverageFuzzer) generateFromGrammar() string {
	// Start with <start> rule
	result := f.expandRule("<start>")

	// Parse as URL and encode properly
	if u, err := url.Parse(result); err == nil {
		return u.String()
	}
	return result
}

// expandRule expands a grammar rule
func (f *CoverageFuzzer) expandRule(rule string) string {
	if alternatives, ok := f.grammar[rule]; ok {
		// Pick random alternative
		alt := alternatives[randInt(len(alternatives))]

		// Expand any nested rules
		for {
			start := -1
			end := -1

			// Find next rule to expand (enclosed in < >)
			for i := 0; i < len(alt); i++ {
				if alt[i] == '<' {
					start = i
				} else if alt[i] == '>' && start != -1 {
					end = i + 1
					break
				}
			}

			if start == -1 || end == -1 {
				break
			}

			// Extract and expand nested rule
			nestedRule := alt[start:end]
			expansion := f.expandRule(nestedRule)

			// Replace in original
			alt = alt[:start] + expansion + alt[end:]
		}
		return alt
	}
	return rule
}

// generateParamValue creates a value for a parameter
func (f *CoverageFuzzer) generateParamValue(param string) string {
	if field, ok := f.form.Fields[param]; ok {
		switch field.Type {
		case "select":
			if len(field.Options) > 0 {
				return field.Options[randInt(len(field.Options))]
			}
		case "number":
			return fmt.Sprintf("%d", randInt(10000))
		case "email":
			return fmt.Sprintf("test%d@example.com", randInt(1000))
		case "checkbox":
			if randBool() {
				return "on"
			}
			return "off"
		}
	}
	return fmt.Sprintf("fuzz%d", randInt(1000))
}

// testInput sends a request with the given input
func (f *CoverageFuzzer) testInput(input string) *Result {
	start := time.Now()

	// Construct full URL
	fullURL := input
	if !isAbsoluteURL(input) {
		fullURL = f.config.TargetURL + input
	}

	// Send request
	resp, err := f.client.Get(fullURL)
	if err != nil {
		return &Result{
			URL:       fullURL,
			Error:     err,
			Duration:  time.Since(start),
			Timestamp: start,
		}
	}
	defer resp.Body.Close()

	// Track coverage
	f.coverage.TrackResponse(resp)
	f.coverage.TrackURL(fullURL)

	return &Result{
		URL:        fullURL,
		StatusCode: resp.StatusCode,
		Duration:   time.Since(start),
		Timestamp:  start,
	}
}

// processResults handles the fuzzing results
func (f *CoverageFuzzer) processResults(results <-chan *Result) {
	for result := range results {
		if f.config.Verbose {
			if result.Error != nil {
				fmt.Printf("[ERROR] %s: %v\n", result.URL, result.Error)
			} else {
				fmt.Printf("[%d] %s (%.2fs)\n",
					result.StatusCode, result.URL, result.Duration.Seconds())
			}
		}
	}
}

// Helper functions

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	return int(randFloat() * float64(n))
}

func randFloat() float64 {
	return float64(time.Now().UnixNano()) / float64(1<<63)
}

func randBool() bool {
	return randInt(2) == 1
}

func randomKey(values url.Values) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	return keys[randInt(len(keys))]
}

func randomMapKey[K comparable, V any](m map[K]V) K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys[randInt(len(keys))]
}

func isAbsoluteURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func readBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	defer resp.Body.Close()

	body := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return body
}
