package html

import (
	"fmt"
	"regexp"
	"strings"
)

// FormField represents an HTML form field
type FormField struct {
	Name     string
	Type     string
	Pattern  string
	Required bool
	Options  []string // For select/datalist elements
}

// Form represents an HTML form
type Form struct {
	Action   string
	Method   string
	Fields   map[string]FormField
	Patterns map[string]string
}

// ParseForm extracts form information from HTML content
func ParseForm(html string) (*Form, error) {
	form := &Form{
		Fields:   make(map[string]FormField),
		Patterns: make(map[string]string),
	}

	// Extract form action
	actionRe := regexp.MustCompile(`<form[^>]+action="([^"]+)"`)
	if matches := actionRe.FindStringSubmatch(html); len(matches) > 1 {
		form.Action = matches[1]
	}

	// Extract form method
	methodRe := regexp.MustCompile(`<form[^>]+method="([^"]+)"`)
	if matches := methodRe.FindStringSubmatch(html); len(matches) > 1 {
		form.Method = strings.ToUpper(matches[1])
	} else {
		form.Method = "GET" // Default method
	}

	// Extract input fields
	inputRe := regexp.MustCompile(`<input[^>]+>`)
	inputs := inputRe.FindAllString(html, -1)
	for _, input := range inputs {
		field := FormField{}

		// Extract name
		nameRe := regexp.MustCompile(`name="([^"]+)"`)
		if matches := nameRe.FindStringSubmatch(input); len(matches) > 1 {
			field.Name = matches[1]
		} else {
			continue // Skip fields without name
		}

		// Extract type
		typeRe := regexp.MustCompile(`type="([^"]+)"`)
		if matches := typeRe.FindStringSubmatch(input); len(matches) > 1 {
			field.Type = matches[1]
		} else {
			field.Type = "text" // Default type
		}

		// Extract pattern
		patternRe := regexp.MustCompile(`pattern="([^"]+)"`)
		if matches := patternRe.FindStringSubmatch(input); len(matches) > 1 {
			field.Pattern = matches[1]
			form.Patterns[field.Name] = field.Pattern
		}

		// Check if required
		field.Required = strings.Contains(input, "required")

		form.Fields[field.Name] = field
	}

	// Extract select fields
	selectRe := regexp.MustCompile(`<select[^>]+name="([^"]+)"[^>]*>(.*?)</select>`)
	selects := selectRe.FindAllStringSubmatch(html, -1)
	for _, sel := range selects {
		name := sel[1]
		content := sel[2]

		field := FormField{
			Name:    name,
			Type:    "select",
			Options: make([]string, 0),
		}

		// Extract options
		optionRe := regexp.MustCompile(`<option[^>]+value="([^"]+)"`)
		options := optionRe.FindAllStringSubmatch(content, -1)
		for _, opt := range options {
			field.Options = append(field.Options, opt[1])
		}

		form.Fields[name] = field
	}

	return form, nil
}

// GenerateGrammar creates a grammar for fuzzing based on the form fields
func (f *Form) GenerateGrammar() map[string][]string {
	grammar := make(map[string][]string)

	// Start rule
	if f.Method == "GET" {
		grammar["<start>"] = []string{"<action>?<query>"}
	} else {
		grammar["<start>"] = []string{"<action>"}
	}

	grammar["<action>"] = []string{f.Action}

	// Build query string from fields
	var queryParts []string
	for name, field := range f.Fields {
		fieldSymbol := fmt.Sprintf("<%s>", name)
		queryParts = append(queryParts, fieldSymbol)

		switch field.Type {
		case "select":
			// Direct values for select fields
			grammar[fieldSymbol] = []string{
				fmt.Sprintf("%s=<value-%s>", name, name),
			}
			valueSymbol := fmt.Sprintf("<value-%s>", name)
			grammar[valueSymbol] = field.Options

		case "number":
			grammar[fieldSymbol] = []string{
				fmt.Sprintf("%s=<number>", name),
			}
			if _, exists := grammar["<number>"]; !exists {
				grammar["<number>"] = []string{
					"<digit>",
					"<digit><number>",
				}
				grammar["<digit>"] = []string{
					"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
				}
			}

		case "email":
			grammar[fieldSymbol] = []string{
				fmt.Sprintf("%s=<email>", name),
			}
			if _, exists := grammar["<email>"]; !exists {
				grammar["<email>"] = []string{
					"<string>@<string>.<string>",
				}
			}

		case "checkbox":
			grammar[fieldSymbol] = []string{
				fmt.Sprintf("%s=<checkbox>", name),
			}
			if _, exists := grammar["<checkbox>"]; !exists {
				grammar["<checkbox>"] = []string{"on", "off"}
			}

		default:
			// Text fields and others
			grammar[fieldSymbol] = []string{
				fmt.Sprintf("%s=<text>", name),
			}
			if pattern, exists := f.Patterns[name]; exists {
				// Convert HTML5 pattern to grammar rules
				grammar[fieldSymbol] = []string{
					fmt.Sprintf("%s=<pattern-%s>", name, name),
				}
				grammar[fmt.Sprintf("<pattern-%s>", name)] = convertPatternToGrammar(pattern)
			}
		}
	}

	// Add query rule combining all fields
	grammar["<query>"] = []string{strings.Join(queryParts, "&")}

	// Add basic text rules if not already present
	if _, exists := grammar["<text>"]; !exists {
		grammar["<text>"] = []string{
			"<string>",
			"<string><text>",
		}
		grammar["<string>"] = []string{
			"<char>",
			"<char><string>",
		}
		grammar["<char>"] = []string{
			"a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
			"k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
			"u", "v", "w", "x", "y", "z",
			"A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
			"K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
			"U", "V", "W", "X", "Y", "Z",
			"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
			"-", "_", ".", "@",
		}
	}

	return grammar
}

// convertPatternToGrammar converts an HTML5 pattern to grammar rules
func convertPatternToGrammar(pattern string) []string {
	// This is a simplified conversion - a full implementation would need
	// to handle all regex patterns
	rules := make([]string, 0)

	// Handle basic character classes
	pattern = strings.ReplaceAll(pattern, "[0-9]", "<digit>")
	pattern = strings.ReplaceAll(pattern, "[a-z]", "<lower>")
	pattern = strings.ReplaceAll(pattern, "[A-Z]", "<upper>")
	pattern = strings.ReplaceAll(pattern, "[a-zA-Z]", "<letter>")

	// Add the converted pattern as a rule
	rules = append(rules, pattern)

	return rules
}
