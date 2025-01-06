package fuzzer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// APIEndpoint represents a detected API endpoint
type APIEndpoint struct {
	URL     string
	Method  string
	Params  map[string]ParamType
	Headers map[string]string
}

// ParamType represents the type and constraints of an API parameter
type ParamType struct {
	Type       string // string, int, float, bool, array, object
	Required   bool
	Format     string // email, date, etc.
	MinValue   float64
	MaxValue   float64
	MinLength  int
	MaxLength  int
	Pattern    string
	Enum       []string
	ArrayType  *ParamType           // For array types
	ObjectType map[string]ParamType // For object types
}

// APIDetector implements detection of API endpoints
type APIDetector struct {
	endpoints map[string]*APIEndpoint
	patterns  []*regexp.Regexp
	config    *Config
}

// NewAPIDetector creates a new API detector
func NewAPIDetector(config *Config) *APIDetector {
	if config == nil {
		config = &Config{
			Verbose: false,
		}
	}

	return &APIDetector{
		endpoints: make(map[string]*APIEndpoint),
		config:    config,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)/api/`),
			regexp.MustCompile(`(?i)/v\d+/`),
			regexp.MustCompile(`(?i)\.json$`),
			regexp.MustCompile(`(?i)/graphql`),
			regexp.MustCompile(`(?i)/rest/`),
			regexp.MustCompile(`(?i)/(get|post|put|delete|patch|anything)$`),
			regexp.MustCompile(`(?i)/data$`),
			regexp.MustCompile(`(?i)/status/\d+$`),
		},
	}
}

// IsAPIEndpoint checks if a URL looks like an API endpoint
func (d *APIDetector) IsAPIEndpoint(urlStr string) bool {
	for _, pattern := range d.patterns {
		if pattern.MatchString(urlStr) {
			return true
		}
	}
	return false
}

// DetectEndpoint analyzes a URL and response to detect API characteristics
func (d *APIDetector) DetectEndpoint(urlStr string, resp *http.Response) (*APIEndpoint, error) {
	// Check content type first
	contentType := resp.Header.Get("Content-Type")
	isJSON := strings.Contains(contentType, "application/json")
	isAPIPattern := d.IsAPIEndpoint(urlStr)

	// Return early if not an API endpoint and not JSON
	if !isAPIPattern && !isJSON {
		return nil, nil
	}

	// Create endpoint object
	endpoint := &APIEndpoint{
		URL:     urlStr,
		Method:  "GET", // Default to GET, can be updated based on form methods
		Params:  make(map[string]ParamType),
		Headers: make(map[string]string),
	}

	// Parse URL parameters
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	// Extract query parameters
	query := parsedURL.Query()
	for param := range query {
		endpoint.Params[param] = d.inferParamType(query.Get(param))
	}

	// Read and parse response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Try to parse as JSON
	var result interface{}
	if err := json.Unmarshal(body, &result); err == nil {
		endpoint.Headers["Content-Type"] = "application/json"
		d.inferJSONStructure(endpoint, result)
		if d.config.Verbose {
			fmt.Printf("Found JSON API endpoint: %s\n", urlStr)
			fmt.Printf("Response structure: %+v\n", result)
		}
	}

	d.endpoints[urlStr] = endpoint
	return endpoint, nil
}

// inferParamType tries to determine the type of a parameter value
func (d *APIDetector) inferParamType(value string) ParamType {
	// Try to parse as different types
	paramType := ParamType{
		Type:     "string",
		Required: false,
	}

	// Check if it's a number
	if regexp.MustCompile(`^-?\d+$`).MatchString(value) {
		paramType.Type = "int"
		return paramType
	}

	// Check if it's a float
	if regexp.MustCompile(`^-?\d*\.\d+$`).MatchString(value) {
		paramType.Type = "float"
		return paramType
	}

	// Check if it's a boolean
	if value == "true" || value == "false" {
		paramType.Type = "bool"
		return paramType
	}

	// Check if it's an email
	if regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`).MatchString(value) {
		paramType.Type = "string"
		paramType.Format = "email"
		return paramType
	}

	// Check if it's a date
	if regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(value) {
		paramType.Type = "string"
		paramType.Format = "date"
		return paramType
	}

	return paramType
}

// inferJSONStructure analyzes JSON response to infer API structure
func (d *APIDetector) inferJSONStructure(endpoint *APIEndpoint, data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			endpoint.Params[key] = d.inferJSONType(val)
		}
	case []interface{}:
		if len(v) > 0 {
			arrayType := d.inferJSONType(v[0])
			endpoint.Params["items"] = ParamType{
				Type:      "array",
				ArrayType: &arrayType,
			}
		}
	}
}

// inferJSONType determines the type of a JSON value
func (d *APIDetector) inferJSONType(value interface{}) ParamType {
	switch v := value.(type) {
	case bool:
		return ParamType{Type: "bool"}
	case float64:
		return ParamType{Type: "float"}
	case string:
		return d.inferParamType(v)
	case map[string]interface{}:
		objType := make(map[string]ParamType)
		for key, val := range v {
			objType[key] = d.inferJSONType(val)
		}
		return ParamType{
			Type:       "object",
			ObjectType: objType,
		}
	case []interface{}:
		if len(v) > 0 {
			arrayType := d.inferJSONType(v[0])
			return ParamType{
				Type:      "array",
				ArrayType: &arrayType,
			}
		}
	}
	return ParamType{Type: "string"}
}

// GetEndpoints returns all detected API endpoints
func (d *APIDetector) GetEndpoints() map[string]*APIEndpoint {
	return d.endpoints
}
