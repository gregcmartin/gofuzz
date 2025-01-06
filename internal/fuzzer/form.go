package fuzzer

// FormField represents an HTML form field
type FormField struct {
	Name     string
	Type     string
	Options  []string // For select/radio fields
	Required bool
	Pattern  string // HTML5 pattern attribute
}
