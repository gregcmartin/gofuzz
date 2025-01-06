package fuzzer

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MutationFuzzer implements mutation-based fuzzing
type MutationFuzzer struct {
	config     *Config
	seedInputs []string
	client     *http.Client
	coverage   map[string]bool // Track unique responses
}

// NewMutationFuzzer creates a new mutation-based fuzzer
func NewMutationFuzzer(config *Config) (*MutationFuzzer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	return &MutationFuzzer{
		config:   config,
		coverage: make(map[string]bool),
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Run starts the fuzzing process
func (f *MutationFuzzer) Run() error {
	if len(f.config.SeedInputs) == 0 {
		return fmt.Errorf("at least one seed input is required")
	}

	// Initialize with seed inputs
	inputs := make([]string, len(f.config.SeedInputs))
	copy(inputs, f.config.SeedInputs)

	// Main fuzzing loop
	for i := 0; i < f.config.NumRequests; i++ {
		// Select an input to mutate
		input := inputs[rand.Intn(len(inputs))]

		// Generate mutations
		numMutations := f.config.MinMutations
		if f.config.MaxMutations > f.config.MinMutations {
			numMutations += rand.Intn(f.config.MaxMutations - f.config.MinMutations + 1)
		}

		mutated := input
		for j := 0; j < numMutations; j++ {
			mutated = f.mutate(mutated)
		}

		// Test the mutated input
		resp, err := f.test(mutated)
		if err != nil {
			if f.config.Verbose {
				fmt.Printf("Error testing %s: %v\n", mutated, err)
			}
			continue
		}

		// Track coverage
		coverage := fmt.Sprintf("%d-%d", resp.StatusCode, len(resp.Header))
		if !f.coverage[coverage] {
			f.coverage[coverage] = true
			if f.config.Verbose {
				fmt.Printf("New coverage: %s with input %s\n", coverage, mutated)
			}
			// Add interesting inputs to the pool
			inputs = append(inputs, mutated)
		}
	}

	return nil
}

// mutate applies a random mutation to the input
func (f *MutationFuzzer) mutate(input string) string {
	// Parse URL to mutate different components
	u, err := url.Parse(input)
	if err != nil {
		return input
	}

	switch rand.Intn(4) {
	case 0: // Mutate path
		parts := strings.Split(u.Path, "/")
		if len(parts) > 0 {
			idx := rand.Intn(len(parts))
			parts[idx] = f.mutateString(parts[idx])
			u.Path = strings.Join(parts, "/")
		}
	case 1: // Mutate query parameter
		q := u.Query()
		if len(q) > 0 {
			// Modify existing parameter
			for k := range q {
				q.Set(k, f.mutateString(q.Get(k)))
				break
			}
		} else {
			// Add new parameter
			q.Set(f.mutateString("param"), f.mutateString("value"))
		}
		u.RawQuery = q.Encode()
	case 2: // Add path traversal
		u.Path = "../" + u.Path
	case 3: // Add special characters
		specialChars := []string{"<", ">", "'", "\"", ";", "%00", "%0d%0a"}
		u.Path += specialChars[rand.Intn(len(specialChars))]
	}

	return u.String()
}

// mutateString applies a random mutation to a string
func (f *MutationFuzzer) mutateString(s string) string {
	if s == "" {
		return "fuzz"
	}

	switch rand.Intn(4) {
	case 0: // Bit flip
		if len(s) > 0 {
			pos := rand.Intn(len(s))
			char := s[pos]
			char ^= byte(1 << uint(rand.Intn(8)))
			return s[:pos] + string(char) + s[pos+1:]
		}
	case 1: // Insert character
		pos := rand.Intn(len(s) + 1)
		char := byte(rand.Intn(256))
		return s[:pos] + string(char) + s[pos:]
	case 2: // Delete character
		if len(s) > 0 {
			pos := rand.Intn(len(s))
			return s[:pos] + s[pos+1:]
		}
	case 3: // Replace with special string
		specials := []string{
			"../../../etc/passwd",
			"<script>alert(1)</script>",
			"' OR '1'='1",
			"%00",
			"../../../../etc/passwd%00",
			"$(cat /etc/passwd)",
			"{{7*7}}",
		}
		return specials[rand.Intn(len(specials))]
	}

	return s
}

// test sends a request with the mutated input
func (f *MutationFuzzer) test(input string) (*http.Response, error) {
	req, err := http.NewRequest("GET", input, nil)
	if err != nil {
		return nil, err
	}

	return f.client.Do(req)
}

func init() {
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())
}
