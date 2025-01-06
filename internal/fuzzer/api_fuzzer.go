package fuzzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIFuzzer implements fuzzing for API endpoints
type APIFuzzer struct {
	endpoint *APIEndpoint
	client   *http.Client
	config   *Config
}

// NewAPIFuzzer creates a new API fuzzer
func NewAPIFuzzer(endpoint *APIEndpoint, config *Config) *APIFuzzer {
	if config == nil {
		config = &Config{
			Verbose:     false,
			MaxWorkers:  10,
			MaxPages:    1000,
			Concurrency: 10,
		}
	}

	return &APIFuzzer{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		config: config,
	}
}

// InferSchema analyzes API responses to infer the schema
func (f *APIFuzzer) InferSchema() error {
	if !f.config.APISchema {
		return nil
	}

	if f.config.Verbose {
		fmt.Printf("Inferring schema for endpoint: %s\n", f.endpoint.URL)
	}

	// Make a request to get sample response
	resp, err := f.client.Get(f.endpoint.URL)
	if err != nil {
		return fmt.Errorf("failed to get sample response: %v", err)
	}
	defer resp.Body.Close()

	// Parse response body
	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	// Infer schema from response
	schema := f.inferJSONSchema(result)

	// Log inferred schema if verbose
	if f.config.Verbose {
		schemaJSON, _ := json.MarshalIndent(schema, "", "  ")
		fmt.Printf("Inferred schema:\n%s\n", string(schemaJSON))
	}

	return nil
}

// inferJSONSchema recursively analyzes JSON structure to build schema
func (f *APIFuzzer) inferJSONSchema(data interface{}) map[string]interface{} {
	schema := make(map[string]interface{})

	switch v := data.(type) {
	case map[string]interface{}:
		properties := make(map[string]interface{})
		for key, val := range v {
			properties[key] = f.inferJSONSchema(val)
		}
		schema["type"] = "object"
		schema["properties"] = properties

	case []interface{}:
		if len(v) > 0 {
			schema["type"] = "array"
			schema["items"] = f.inferJSONSchema(v[0])
		} else {
			schema["type"] = "array"
			schema["items"] = map[string]interface{}{"type": "any"}
		}

	case string:
		schema["type"] = "string"
		if isEmail(v) {
			schema["format"] = "email"
		} else if isDate(v) {
			schema["format"] = "date"
		}

	case float64:
		if v == float64(int64(v)) {
			schema["type"] = "integer"
		} else {
			schema["type"] = "number"
		}

	case bool:
		schema["type"] = "boolean"

	case nil:
		schema["type"] = "null"
	}

	return schema
}

// Helper functions for schema inference
func isEmail(s string) bool {
	return strings.Contains(s, "@") && strings.Contains(s, ".")
}

func isDate(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// Run starts the API fuzzing process
func (f *APIFuzzer) Run() error {
	// Generate test cases based on parameter types
	testCases := f.generateTestCases()

	for _, testCase := range testCases {
		if err := f.executeTestCase(testCase); err != nil {
			if f.config.Verbose {
				fmt.Printf("[ERROR] Test case failed: %v\n", err)
			}
			continue
		}
	}

	return nil
}

// generateTestCases creates test cases based on parameter types
func (f *APIFuzzer) generateTestCases() []map[string]interface{} {
	var testCases []map[string]interface{}

	// Generate base test case with valid values
	baseCase := make(map[string]interface{})
	for name, param := range f.endpoint.Params {
		baseCase[name] = f.generateValidValue(param)
	}
	testCases = append(testCases, baseCase)

	// Generate edge cases
	for name, param := range f.endpoint.Params {
		// Create variations of the base case with edge cases for each parameter
		edgeCases := f.generateEdgeCases(param)
		for _, edgeValue := range edgeCases {
			testCase := copyMap(baseCase)
			testCase[name] = edgeValue
			testCases = append(testCases, testCase)
		}
	}

	return testCases
}

// generateValidValue generates a valid value for a parameter type
func (f *APIFuzzer) generateValidValue(param ParamType) interface{} {
	switch param.Type {
	case "string":
		if param.Format == "email" {
			return f.generateEmail()
		}
		if param.Format == "date" {
			return f.generateDate()
		}
		return f.generateString(10)
	case "int":
		min := int(param.MinValue)
		if min == 0 {
			min = -100
		}
		max := int(param.MaxValue)
		if max == 0 {
			max = 100
		}
		return rand.Intn(max-min) + min
	case "float":
		min := param.MinValue
		if min == 0 {
			min = -100.0
		}
		max := param.MaxValue
		if max == 0 {
			max = 100.0
		}
		return min + rand.Float64()*(max-min)
	case "bool":
		return rand.Intn(2) == 1
	case "array":
		if param.ArrayType == nil {
			return []interface{}{}
		}
		arr := make([]interface{}, rand.Intn(5)+1)
		for i := range arr {
			arr[i] = f.generateValidValue(*param.ArrayType)
		}
		return arr
	case "object":
		if len(param.ObjectType) == 0 {
			return map[string]interface{}{}
		}
		obj := make(map[string]interface{})
		for key, fieldType := range param.ObjectType {
			obj[key] = f.generateValidValue(fieldType)
		}
		return obj
	default:
		return ""
	}
}

// generateEdgeCases generates edge cases for a parameter type
func (f *APIFuzzer) generateEdgeCases(param ParamType) []interface{} {
	var cases []interface{}

	// Add null/empty cases
	cases = append(cases, nil, "")

	switch param.Type {
	case "string":
		cases = append(cases,
			strings.Repeat("a", 1000),   // Very long string
			"<script>alert(1)</script>", // XSS attempt
			"'; DROP TABLE users; --",   // SQL injection attempt
			"../../../etc/passwd",       // Path traversal attempt
			"\u0000dangerous",           // Null byte injection
			"🦊⚡️🌟",                      // Unicode/emoji
		)
	case "int":
		cases = append(cases,
			0,
			-1,
			1,
			-9999999999,
			9999999999,
			"123", // Type confusion
		)
	case "float":
		cases = append(cases,
			0.0,
			1.0,
			-1.0,
			math.MaxFloat64,
			-math.MaxFloat64,
			"123.45", // Type confusion
		)
	case "bool":
		cases = append(cases,
			"true",  // Type confusion
			"false", // Type confusion
			1,       // Type confusion
			0,       // Type confusion
		)
	case "array":
		cases = append(cases,
			[]interface{}{},                        // Empty array
			make([]interface{}, 1000),              // Very large array
			"not_an_array",                         // Type confusion
			[]interface{}{nil, nil},                // Array with null values
			map[string]interface{}{"key": "value"}, // Type confusion
		)
	case "object":
		cases = append(cases,
			map[string]interface{}{},                               // Empty object
			[]interface{}{},                                        // Type confusion
			map[string]interface{}{"": nil},                        // Empty key
			map[string]interface{}{"a": strings.Repeat("b", 1000)}, // Large value
		)
	}

	return cases
}

// executeTestCase sends a request with the test case data
func (f *APIFuzzer) executeTestCase(testCase map[string]interface{}) error {
	var req *http.Request
	var err error

	switch f.endpoint.Method {
	case "GET":
		// Build query string
		query := url.Values{}
		for key, value := range testCase {
			query.Set(key, fmt.Sprintf("%v", value))
		}
		reqURL := f.endpoint.URL
		if len(query) > 0 {
			if strings.Contains(reqURL, "?") {
				reqURL += "&" + query.Encode()
			} else {
				reqURL += "?" + query.Encode()
			}
		}
		req, err = http.NewRequest("GET", reqURL, nil)

	case "POST", "PUT", "PATCH":
		// Send as JSON body
		body, err := json.Marshal(testCase)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %v", err)
		}
		req, err = http.NewRequest(f.endpoint.Method, f.endpoint.URL, bytes.NewBuffer(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

	default:
		return fmt.Errorf("unsupported HTTP method: %s", f.endpoint.Method)
	}

	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Add any custom headers
	for key, value := range f.endpoint.Headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Log response details in verbose mode
	if f.config.Verbose {
		fmt.Printf("[%s] %s -> %d\n", f.endpoint.Method, req.URL, resp.StatusCode)
	}

	return nil
}

// Helper function to copy a map
func copyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// Helper functions for generating test data
func (f *APIFuzzer) generateEmail() string {
	return fmt.Sprintf("test%d@example.com", rand.Intn(10000))
}

func (f *APIFuzzer) generateDate() string {
	min := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	max := time.Now().Unix()
	delta := max - min
	sec := rand.Int63n(delta) + min
	return time.Unix(sec, 0).Format("2006-01-02")
}

func (f *APIFuzzer) generateString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
