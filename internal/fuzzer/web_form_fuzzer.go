package fuzzer

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// WebFormFuzzer implements fuzzing for HTML forms
type WebFormFuzzer struct {
	*GrammarCoverageFuzzer
	targetURL string
	formURL   string
}

// NewWebFormFuzzer creates a new web form fuzzer
func NewWebFormFuzzer(formURL string) (*WebFormFuzzer, error) {
	if formURL == "" {
		return nil, fmt.Errorf("form URL cannot be empty")
	}

	// Parse and validate the URL
	parsedURL, err := url.Parse(formURL)
	if err != nil {
		return nil, fmt.Errorf("invalid form URL: %v", err)
	}

	// Ensure URL has a scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		formURL = parsedURL.String()
		parsedURL, err = url.Parse(formURL) // Re-parse with scheme
		if err != nil {
			return nil, fmt.Errorf("invalid form URL after adding scheme: %v", err)
		}
	}

	// Get HTML content
	htmlContent, err := getHTML(formURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get HTML: %v", err)
	}

	// Extract form grammar
	grammar, err := extractFormGrammar(htmlContent, formURL, parsedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract grammar: %v", err)
	}

	// Create base fuzzer with extracted grammar
	config := &Config{
		UseCoverage:        true,
		UseGrammarCoverage: true,
		MaxDepth:           10,
	}

	baseFuzzer, err := NewGrammarCoverageFuzzer(config)
	if err != nil {
		return nil, err
	}

	// Set the extracted grammar
	baseFuzzer.grammar = grammar

	fuzzer := &WebFormFuzzer{
		GrammarCoverageFuzzer: baseFuzzer,
		targetURL:             parsedURL.String(), // Use normalized URL
		formURL:               parsedURL.String(),
	}

	return fuzzer, nil
}

// FormGrammar represents a grammar extracted from an HTML form
type FormGrammar struct {
	Action string               // Form action URL
	Method string               // Form method (GET/POST)
	Fields map[string]FormField // Form fields
}

// extractFormGrammar extracts a grammar from HTML form elements
func extractFormGrammar(htmlContent string, baseURL string, parsedBase *url.URL) (Grammar, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}

	grammar := make(Grammar)
	formGrammar := &FormGrammar{
		Fields: make(map[string]FormField),
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "form":
				// Extract form attributes
				for _, attr := range n.Attr {
					switch attr.Key {
					case "action":
						formGrammar.Action = attr.Val
					case "method":
						formGrammar.Method = attr.Val
					}
				}
			case "input", "select", "textarea":
				field := FormField{}
				name := ""
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "type":
						field.Type = attr.Val
					case "required":
						field.Required = true
					case "pattern":
						field.Pattern = attr.Val
					}
				}
				if name != "" {
					if n.Data == "select" {
						field.Type = "select"
						field.Options = extractSelectOptions(n)
					}
					formGrammar.Fields[name] = field
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	// Convert form grammar to fuzzing grammar
	action := formGrammar.Action
	method := strings.ToUpper(formGrammar.Method)
	if method == "" {
		method = "GET"
	}

	if action == "" {
		// If no action specified, use the current URL
		action = baseURL
	} else if !strings.HasPrefix(action, "http") {
		// Parse action as relative URL
		actionURL, err := url.Parse(action)
		if err != nil {
			return nil, fmt.Errorf("invalid action URL: %v", err)
		}

		// Resolve relative URL against base URL
		action = parsedBase.ResolveReference(actionURL).String()
	}

	// Add method and action to grammar
	if method == "GET" {
		grammar["<start>"] = []string{method + " " + action + "?<query>"}
	} else {
		grammar["<start>"] = []string{method + " " + action + " <query>"}
	}

	// Build query string from fields
	var queryParts []string
	for name, field := range formGrammar.Fields {
		fieldSymbol := "<" + name + ">"
		queryParts = append(queryParts, name+"="+fieldSymbol)

		// Add field-specific rules
		switch field.Type {
		case "text", "":
			grammar[fieldSymbol] = []string{"<text>"}
		case "email":
			grammar[fieldSymbol] = []string{"<email>"}
		case "number":
			grammar[fieldSymbol] = []string{"<number>"}
		case "select":
			grammar[fieldSymbol] = field.Options
		case "checkbox":
			grammar[fieldSymbol] = []string{"on", "off"}
		default:
			grammar[fieldSymbol] = []string{"<text>"}
		}
	}
	grammar["<query>"] = []string{strings.Join(queryParts, "&")}

	// Add base rules for common types
	grammar["<text>"] = []string{"<string>"}
	grammar["<string>"] = []string{"<letter>", "<letter><string>"}
	grammar["<letter>"] = []string{"<plus>", "<percent>", "<other>"}
	grammar["<plus>"] = []string{"+"}
	grammar["<percent>"] = []string{"%<hexdigit><hexdigit>"}
	grammar["<hexdigit>"] = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}
	grammar["<other>"] = []string{"0", "1", "2", "3", "4", "5", "a", "b", "c", "d", "e", "-", "_"}
	grammar["<number>"] = []string{"<digits>"}
	grammar["<digits>"] = []string{"<digit>", "<digits><digit>"}
	grammar["<digit>"] = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	grammar["<email>"] = []string{"<string>@<string>"}

	return grammar, nil
}

// extractSelectOptions extracts options from a select element
func extractSelectOptions(n *html.Node) []string {
	var options []string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "option" {
			for _, attr := range n.Attr {
				if attr.Key == "value" {
					options = append(options, attr.Val)
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return options
}

// getHTML retrieves HTML content from a URL
func getHTML(urlStr string) (string, error) {
	// Parse and validate the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	// Ensure URL has a scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		urlStr = parsedURL.String()
	}

	// Create a client with reasonable timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		return "", fmt.Errorf("failed to fetch URL: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	return string(body), nil
}

// Run starts the fuzzing process
func (f *WebFormFuzzer) Run() error {
	// Create derivation tree
	tree := f.generateDerivationTree("<start>", 0)

	// Track coverage
	f.grammarCoverage.TrackDerivationTree(tree)

	// Get form data from tree
	formData := f.treeToString(tree)
	if formData == "" {
		return fmt.Errorf("no form data generated")
	}

	// Create client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Parse form data into method and URL
	parts := strings.SplitN(formData, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("invalid form data format")
	}

	method := parts[0]
	targetURL := parts[1]
	var queryData string
	if len(parts) > 2 {
		queryData = parts[2]
	}

	// Parse and validate the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	// Ensure URL has a scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		targetURL = parsedURL.String()
	}

	// Create base request
	var req *http.Request
	if method == "GET" {
		// For GET, append query params to URL
		if queryData != "" {
			if strings.Contains(targetURL, "?") {
				targetURL += "&" + queryData
			} else {
				targetURL += "?" + queryData
			}
		}
		req, err = http.NewRequest("GET", targetURL, nil)
	} else {
		// For POST, put query params in body
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(queryData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Process response
	if resp.StatusCode != http.StatusOK {
		if f.config.Verbose {
			fmt.Printf("[ERROR] %s: %d\n", req.URL.String(), resp.StatusCode)
		}
		return fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	if f.config.Verbose {
		fmt.Printf("[OK] %s\n", req.URL.String())
	}

	return nil
}
