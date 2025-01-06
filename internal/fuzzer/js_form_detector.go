package fuzzer

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// JSFormDetector implements detection of JavaScript-rendered forms
type JSFormDetector struct {
	url      string
	timeout  time.Duration
	maxDepth int
}

// JSForm represents a form detected in JavaScript
type JSForm struct {
	Action string    `json:"action"`
	Method string    `json:"method"`
	Fields []JSField `json:"fields"`
}

// JSField represents a form field detected in JavaScript
type JSField struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Pattern  string `json:"pattern"`
}

// NewJSFormDetector creates a new JavaScript form detector
func NewJSFormDetector(url string, timeout time.Duration) *JSFormDetector {
	return &JSFormDetector{
		url:      url,
		timeout:  timeout,
		maxDepth: 5,
	}
}

// DetectForms finds JavaScript-rendered forms in the page
func (d *JSFormDetector) DetectForms() ([]FormField, error) {
	// Create Chrome instance
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Add timeout
	ctx, cancel = context.WithTimeout(ctx, d.timeout)
	defer cancel()

	var forms []JSForm

	// Actions to execute
	actions := []chromedp.Action{
		// Navigate to page
		chromedp.Navigate(d.url),

		// Wait for page load
		chromedp.WaitVisible("body", chromedp.ByQuery),

		// Extract forms
		chromedp.Evaluate(`
			(() => {
				const forms = [];
				
				// Helper to create a form object
				const createForm = (element, fields) => {
					let action = element.getAttribute('action');
					// Handle relative URLs
					if (action && !action.startsWith('http')) {
						// Handle absolute paths
						if (action.startsWith('/')) {
							const url = new URL(window.location.href);
							action = url.protocol + '//' + url.host + action;
						} else {
							// Handle relative paths
							action = new URL(action, window.location.href).href;
						}
					}
					// Default to current URL if no action specified
					action = action || window.location.href;

					return {
						action: action,
						method: element.getAttribute('method') || 'POST',
						fields: fields
					};
				};

				// Helper to create a field object
				const createField = (element) => {
					// Skip meta tags and non-interactive elements
					if (element.tagName.toLowerCase() === 'meta' || 
						element.getAttribute('type') === 'hidden' ||
						element.hasAttribute('aria-hidden') ||
						element.style.display === 'none' ||
						element.style.visibility === 'hidden') {
						return null;
					}

					// Get field name from various attributes
					const name = element.getAttribute('name') || 
							  element.getAttribute('formControlName') || 
							  element.getAttribute('v-model') ||
							  element.getAttribute('data-field-name') ||
							  element.getAttribute('id') ||
							  element.getAttribute('aria-label');

					// Skip if no valid name found
					if (!name) {
						return null;
					}

					// Get field type
					let type = element.getAttribute('type') || 'text';
					if (element.tagName.toLowerCase() === 'select') {
						type = 'select';
					} else if (element.tagName.toLowerCase() === 'textarea') {
						type = 'textarea';
					}

					// Validate field is actually part of a form-like interface
					const isFormField = element.tagName.toLowerCase() === 'input' ||
									element.tagName.toLowerCase() === 'select' ||
									element.tagName.toLowerCase() === 'textarea' ||
									element.getAttribute('role') === 'textbox' ||
									element.getAttribute('role') === 'combobox' ||
									element.getAttribute('contenteditable') === 'true' ||
									element.classList.contains('form-control') ||
									element.classList.contains('input-field') ||
									element.closest('[role="form"]') !== null;

					if (!isFormField) {
						return null;
					}

					return {
						name: name,
						type: type,
						required: element.hasAttribute('required') || 
								element.getAttribute('aria-required') === 'true',
						pattern: element.getAttribute('pattern') || 
								element.getAttribute('data-pattern') ||
								element.getAttribute('data-validation')
					};
				};

				// Find traditional forms
				document.querySelectorAll('form').forEach(form => {
					const fields = [];
					form.querySelectorAll('input, select, textarea').forEach(field => {
						if (field.name) {
							fields.push(createField(field));
						}
					});
					forms.push(createForm(form, fields));
				});

				// Find framework-specific and generic forms
				const formSelectors = [
					// Framework-specific form indicators
					'[data-form]',
					'[ng-form]',
					'[v-form]',
					'[formGroup]',
					'[data-component="form"]',
					'[role="form"]',
					'[is="form"]',
					'[data-testid*="form"]',
					'[class*="form"]',
					'[id*="form"]',

					// Common form wrapper classes
					'.form-wrapper',
					'.form-container',
					'.form-group',
					'.form-section',
					
					// Common form patterns
					'[class*="signup"]',
					'[class*="login"]',
					'[class*="contact"]',
					'[class*="search"]',
					'[class*="filter"]',
					'[class*="subscribe"]',
					'[class*="checkout"]',
					'[class*="payment"]'
				];

				// Enhanced field detection
				const fieldSelectors = [
					// Standard form controls
					'input:not([type="hidden"])',
					'select',
					'textarea',
					'button[type="submit"]',

					// Framework bindings
					'[ng-model]',
					'[v-model]',
					'[formControlName]',
					'[data-bind]',
					'[x-model]',

					// Common field patterns
					'[name]',
					'[aria-label]',
					'[placeholder]',
					'[data-field]',
					'[data-input]',
					'.form-control',
					'.input-field',
					'[class*="input"]',
					'[class*="field"]',
					'[role="textbox"]',
					'[role="combobox"]',
					'[role="listbox"]',
					'[contenteditable="true"]'
				];

				// Find all potential form containers
				formSelectors.forEach(selector => {
					document.querySelectorAll(selector).forEach(container => {
						const fields = [];
						
						// Look for fields within this container
						fieldSelectors.forEach(fieldSelector => {
							container.querySelectorAll(fieldSelector).forEach(field => {
								// Skip if field is already part of a traditional form
								if (!field.closest('form')) {
									const fieldObj = createField(field);
									if (fieldObj) {
										fields.push(fieldObj);
									}
								}
							});
						});

						// Only create a form if we found valid fields
						if (fields.length > 0) {
							forms.push(createForm(container, fields));
						}
					});
				});

				// Look for orphaned fields (not in any container)
				fieldSelectors.forEach(selector => {
					document.querySelectorAll(selector).forEach(field => {
						// Skip if field is already part of a form or known container
						if (!field.closest('form') && !formSelectors.some(s => field.closest(s))) {
							const fields = [createField(field)];
							// Look for related fields in the same parent
							const parent = field.parentElement;
							if (parent) {
								fieldSelectors.forEach(s => {
									parent.querySelectorAll(s).forEach(sibling => {
										if (sibling !== field && !sibling.closest('form')) {
											const fieldObj = createField(sibling);
											if (fieldObj) {
												fields.push(fieldObj);
											}
										}
									});
								});
							}
							forms.push(createForm(parent || field, fields));
						}
					});
				});

				return forms;
			})()
		`, &forms),
	}

	// Execute actions
	if err := chromedp.Run(ctx, actions...); err != nil {
		return nil, fmt.Errorf("failed to execute actions: %v", err)
	}

	// Convert JS forms to FormField structs
	var formFields []FormField
	for _, form := range forms {
		for _, field := range form.Fields {
			if field.Name != "" { // Only include fields with names
				formFields = append(formFields, FormField{
					Name:     field.Name,
					Type:     field.Type,
					Required: field.Required,
					Pattern:  field.Pattern,
				})
			}
		}
	}

	return formFields, nil
}

// WaitForDynamicContent waits for dynamic content to load
func (d *JSFormDetector) WaitForDynamicContent(ctx context.Context) error {
	selectors := []string{
		// Loading states
		"[data-loading]", "[data-loaded]", ".loading", ".loaded",
		"[aria-busy='true']", "[aria-live]", ".spinner", ".loader",
		"[class*='loading']", "[class*='loader']",

		// Framework roots and dynamic regions
		"#app", "#root", "#main", "[ng-app]", "[data-app]",
		"[data-view]", "[data-page]", "[data-component]",
		"[x-data]", "[data-reactroot]", "[data-hydrated]",

		// Dynamic content indicators
		"[data-dynamic]", "[data-async]", "[data-remote]",
		"[data-fetch]", "[data-ajax]", "[data-content]",
		"[aria-live='polite']", "[aria-live='assertive']",

		// Common interactive regions
		"[role='tabpanel']", "[role='dialog']",
		"[role='alert']", "[role='status']",
		"[data-region]", "[data-section]",
		".dynamic-content", ".async-content",

		// State indicators
		"[data-state]", "[data-status]",
		"[data-loaded='true']", "[data-ready='true']",
		".initialized", ".rendered",
	}

	for _, selector := range selectors {
		// Try to wait for element to be visible
		if err := chromedp.Run(ctx, chromedp.WaitVisible(selector, chromedp.ByQuery)); err == nil {
			log.Printf("Found dynamic content: %s\n", selector)
			return nil
		}
	}

	return nil
}

// MonitorNetworkActivity monitors XHR/fetch requests
func (d *JSFormDetector) MonitorNetworkActivity(ctx context.Context) error {
	// Listen for network events
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			if e.Request.Method == "POST" {
				log.Printf("Detected form submission to: %s\n", e.Request.URL)
			}
		}
	})

	return nil
}
