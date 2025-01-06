package fuzzer

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
)

// Coverage tracks which parts of the application have been tested
type Coverage struct {
	// Map of response hash to count of times seen
	responses map[string]int
	// Map of status code to count of times seen
	statusCodes map[int]int
	// Map of unique paths tested
	paths map[string]bool
	// Map of unique parameters tested
	params map[string]bool
	// Map of unique parameter values tested
	values map[string]map[string]bool
	// Protect concurrent access
	mu sync.RWMutex
}

// NewCoverage creates a new Coverage tracker
func NewCoverage() *Coverage {
	return &Coverage{
		responses:   make(map[string]int),
		statusCodes: make(map[int]int),
		paths:       make(map[string]bool),
		params:      make(map[string]bool),
		values:      make(map[string]map[string]bool),
	}
}

// TrackResponse records a response and returns true if it's new
func (c *Coverage) TrackResponse(resp *http.Response) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	isNew := false

	// Track status code
	if _, exists := c.statusCodes[resp.StatusCode]; !exists {
		isNew = true
	}
	c.statusCodes[resp.StatusCode]++

	// Track response body hash
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return isNew
	}
	resp.Body.Close()

	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	if _, exists := c.responses[hash]; !exists {
		isNew = true
	}
	c.responses[hash]++

	return isNew
}

// TrackURL records URL components and returns true if anything is new
func (c *Coverage) TrackURL(urlStr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	isNew := false
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Track path
	if !c.paths[parsedURL.Path] {
		c.paths[parsedURL.Path] = true
		isNew = true
	}

	// Track query parameters and values
	query := parsedURL.Query()
	for param, values := range query {
		if !c.params[param] {
			c.params[param] = true
			isNew = true
		}

		if c.values[param] == nil {
			c.values[param] = make(map[string]bool)
		}

		for _, value := range values {
			if !c.values[param][value] {
				c.values[param][value] = true
				isNew = true
			}
		}
	}

	return isNew
}

// GetStats returns coverage statistics
func (c *Coverage) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := make(map[string]interface{})

	// Unique responses seen
	stats["unique_responses"] = len(c.responses)

	// Status code distribution
	statusDist := make(map[int]int)
	for code, count := range c.statusCodes {
		statusDist[code] = count
	}
	stats["status_codes"] = statusDist

	// Unique paths tested
	var paths []string
	for path := range c.paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	stats["paths"] = paths

	// Parameter coverage
	paramStats := make(map[string]interface{})
	for param := range c.params {
		valueCount := 0
		if c.values[param] != nil {
			valueCount = len(c.values[param])
		}
		paramStats[param] = map[string]int{
			"unique_values": valueCount,
		}
	}
	stats["parameters"] = paramStats

	return stats
}

// GetUniqueResponseCount returns the number of unique responses seen
func (c *Coverage) GetUniqueResponseCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.responses)
}

// GetUniquePaths returns all unique paths tested
func (c *Coverage) GetUniquePaths() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var paths []string
	for path := range c.paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// GetUniqueParams returns all unique parameters tested
func (c *Coverage) GetUniqueParams() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var params []string
	for param := range c.params {
		params = append(params, param)
	}
	sort.Strings(params)
	return params
}

// GetParamValues returns all unique values tested for a parameter
func (c *Coverage) GetParamValues(param string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.values[param] == nil {
		return nil
	}

	var values []string
	for value := range c.values[param] {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

// HasNewCoverage checks if a URL would provide new coverage
func (c *Coverage) HasNewCoverage(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if path is new
	if !c.paths[parsedURL.Path] {
		return true
	}

	// Check if any parameters or values are new
	query := parsedURL.Query()
	for param, values := range query {
		if !c.params[param] {
			return true
		}

		if c.values[param] == nil {
			return true
		}

		for _, value := range values {
			if !c.values[param][value] {
				return true
			}
		}
	}

	return false
}

// Reset clears all coverage data
func (c *Coverage) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.responses = make(map[string]int)
	c.statusCodes = make(map[int]int)
	c.paths = make(map[string]bool)
	c.params = make(map[string]bool)
	c.values = make(map[string]map[string]bool)
}
