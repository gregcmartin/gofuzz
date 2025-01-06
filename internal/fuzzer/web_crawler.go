package fuzzer

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"
)

// WebCrawler implements web application crawling
type WebCrawler struct {
	baseURL        *url.URL
	visited        map[string]bool
	forms          map[string][]FormField
	formSignatures map[string]bool // Track unique form signatures
	maxPages       int
	concurrent     bool
	maxWorkers     int
	config         *Config
	visitedLock    sync.RWMutex
	formsLock      sync.RWMutex
	signaturesLock sync.RWMutex
	stopCrawl      chan struct{} // Signal to stop crawling
	apiDetector    *APIDetector  // API endpoint detector
}

// NewWebCrawler creates a new web crawler
func NewWebCrawler(baseURL string, maxPages int, concurrent bool, config *Config) (*WebCrawler, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = &Config{
			Verbose:     false,
			Concurrency: 20,
			MaxWorkers:  20,
			MaxPages:    1000,
		}
	}

	return &WebCrawler{
		baseURL:        parsed,
		visited:        make(map[string]bool),
		forms:          make(map[string][]FormField),
		formSignatures: make(map[string]bool),
		maxPages:       maxPages,
		concurrent:     concurrent,
		maxWorkers:     config.MaxWorkers,
		config:         config,
		stopCrawl:      make(chan struct{}),
		apiDetector:    NewAPIDetector(config),
	}, nil
}

// SetMaxWorkers sets the maximum number of concurrent workers
func (c *WebCrawler) SetMaxWorkers(workers int) {
	if workers <= 0 {
		workers = 20 // Default to 20 workers
	}
	if workers > 100 {
		workers = 100 // Cap at 100 workers
	}
	c.maxWorkers = workers
}

// Crawl starts crawling from the base URL
func (c *WebCrawler) Crawl() error {
	if c.concurrent {
		return c.crawlConcurrent(c.baseURL.String())
	}
	return c.crawlSequential(c.baseURL.String())
}

// crawlSequential performs sequential crawling
func (c *WebCrawler) crawlSequential(startURL string) error {
	noNewFormsSince := time.Now()

	var crawl func(string) error
	crawl = func(url string) error {
		if c.isVisited(url) || !c.isSameHost(url) {
			return nil
		}

		c.markVisited(url)

		// Get page content
		if c.config.Verbose {
			log.Printf("Crawling URL: %s\n", url)
		}
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("Error fetching %s: %v\n", url, err)
			return err
		}
		defer resp.Body.Close()

		// Check for security blocks
		if block, err := DetectSecurityProtection(resp); err != nil {
			log.Printf("Error checking security protection: %v\n", err)
		} else if block != nil {
			log.Printf("Security protection detected!\nType: %s\nDescription: %s\nEvidence: %s\n",
				block.Type, block.Description, block.Evidence)
			return fmt.Errorf("security protection detected: %s", block.Type)
		}

		// Check if API fuzzing is enabled
		if c.config.APIFuzzing {
			// Check if this is an API endpoint
			if endpoint, err := c.apiDetector.DetectEndpoint(url, resp); err != nil {
				if c.config.Verbose {
					log.Printf("Error detecting API endpoint %s: %v\n", url, err)
				}
			} else if endpoint != nil {
				if c.config.Verbose {
					log.Printf("Found API endpoint: %s\n", url)
				}
				// Fuzz the API endpoint
				fuzzer := NewAPIFuzzer(endpoint, c.config)
				if err := fuzzer.Run(); err != nil {
					log.Printf("Error fuzzing API endpoint %s: %v\n", url, err)
				}

				// Perform schema inference if enabled
				if c.config.APISchema {
					if c.config.Verbose {
						log.Printf("Inferring schema for API endpoint: %s\n", url)
					}
					if err := fuzzer.InferSchema(); err != nil {
						log.Printf("Error inferring schema for API endpoint %s: %v\n", url, err)
					}
				}
			}
		}

		// Parse HTML
		doc, err := html.Parse(resp.Body)
		if err != nil {
			log.Printf("Error parsing HTML from %s: %v\n", url, err)
			return err
		}

		// Extract and add forms
		foundNew := false

		// Extract static forms
		staticForms := c.extractForms(doc)
		if len(staticForms) > 0 {
			if c.addForms(url, staticForms) {
				foundNew = true
			}
		}

		// Extract JavaScript forms
		jsDetector := NewJSFormDetector(url, 10*time.Second)
		jsForms, err := jsDetector.DetectForms()
		if err == nil && len(jsForms) > 0 {
			if c.addForms(url, jsForms) {
				foundNew = true
			}
		}

		// Update last new form time
		if foundNew {
			noNewFormsSince = time.Now()
		} else if time.Since(noNewFormsSince) > 15*time.Second {
			if c.config.Verbose {
				log.Printf("No new forms found for 15 seconds, stopping crawl\n")
			}
			select {
			case <-c.stopCrawl: // Check if already closed
			default:
				close(c.stopCrawl)
			}
			return nil
		}

		// Extract links
		links := c.extractLinks(doc)
		for _, link := range links {
			select {
			case <-c.stopCrawl:
				return nil
			default:
				if len(c.visited) >= c.maxPages {
					return nil
				}
				if err := crawl(link); err != nil {
					return err
				}
			}
		}

		return nil
	}

	return crawl(startURL)
}

// crawlConcurrent performs concurrent crawling
func (c *WebCrawler) crawlConcurrent(startURL string) error {
	var (
		wg              sync.WaitGroup
		noNewFormsSince = time.Now()
		timeLock        sync.Mutex
		urlQueue        = make(chan string, 10000)
		workQueue       = make(chan struct{}, c.maxWorkers) // Limit concurrent work
		done            = make(chan struct{})               // Signal completion
		pendingWork     = int32(1)                          // Start with 1 for initial URL
	)

	// Start URL processor workers
	for i := 0; i < c.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-c.stopCrawl:
					return
				case url, ok := <-urlQueue:
					if !ok {
						return
					}

					workQueue <- struct{}{} // Acquire work slot
					if !c.isVisited(url) && c.isSameHost(url) {
						c.markVisited(url)
						c.processURL(url, urlQueue, &noNewFormsSince, &timeLock, &pendingWork)
					} else {
						atomic.AddInt32(&pendingWork, -1) // Decrement pending work
					}
					<-workQueue // Release work slot
				}
			}
		}()
	}

	// Monitor completion
	go func() {
		for {
			if atomic.LoadInt32(&pendingWork) == 0 {
				select {
				case <-c.stopCrawl:
					return
				default:
					close(c.stopCrawl)
					close(done)
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Add initial URL
	urlQueue <- startURL

	// Wait for completion or stop signal
	select {
	case <-done:
	case <-c.stopCrawl:
	}

	// Cleanup
	close(urlQueue)
	wg.Wait()

	return nil
}

// processURL processes a single URL, extracting forms and links
func (c *WebCrawler) processURL(url string, urlQueue chan<- string, noNewFormsSince *time.Time, timeLock *sync.Mutex, pendingWork *int32) {
	// Get page content
	resp, err := http.Get(url)
	if err != nil {
		if c.config.Verbose {
			log.Printf("Error fetching %s: %v\n", url, err)
		}
		return
	}
	defer resp.Body.Close()

	// Check if API fuzzing is enabled
	if c.config.APIFuzzing {
		if endpoint, err := c.apiDetector.DetectEndpoint(url, resp); err != nil {
			if c.config.Verbose {
				log.Printf("Error detecting API endpoint %s: %v\n", url, err)
			}
		} else if endpoint != nil {
			if c.config.Verbose {
				log.Printf("Found API endpoint: %s\n", url)
			}
			fuzzer := NewAPIFuzzer(endpoint, c.config)
			if err := fuzzer.Run(); err != nil {
				log.Printf("Error fuzzing API endpoint %s: %v\n", url, err)
			}
			if c.config.APISchema {
				if err := fuzzer.InferSchema(); err != nil {
					log.Printf("Error inferring schema for API endpoint %s: %v\n", url, err)
				}
			}
		}
	}

	// Check for security blocks
	if block, err := DetectSecurityProtection(resp); err != nil {
		if c.config.Verbose {
			log.Printf("Error checking security protection: %v\n", err)
		}
	} else if block != nil {
		if c.config.Verbose {
			log.Printf("Security protection detected!\nType: %s\nDescription: %s\nEvidence: %s\n",
				block.Type, block.Description, block.Evidence)
		}
		return
	}

	// Parse HTML
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return
	}

	// Extract and add forms
	foundNew := false

	staticForms := c.extractForms(doc)
	if len(staticForms) > 0 && c.addForms(url, staticForms) {
		foundNew = true
	}

	jsDetector := NewJSFormDetector(url, 10*time.Second)
	if jsForms, err := jsDetector.DetectForms(); err == nil && len(jsForms) > 0 {
		if c.addForms(url, jsForms) {
			foundNew = true
			if c.config.Verbose {
				log.Printf("Found new unique form at %s with %d fields\n", url, len(jsForms))
			}
		}
	}

	// Update last new form time
	if foundNew {
		timeLock.Lock()
		*noNewFormsSince = time.Now()
		timeLock.Unlock()
	} else {
		timeLock.Lock()
		elapsed := time.Since(*noNewFormsSince)
		timeLock.Unlock()
		if elapsed > 15*time.Second {
			if c.config.Verbose {
				log.Printf("No new forms found for 15 seconds, stopping crawl\n")
			}
			select {
			case <-c.stopCrawl:
			default:
				close(c.stopCrawl)
			}
			return
		}
	}

	// Add new links to queue and update pending work count
	links := c.extractLinks(doc)
	if len(links) > 0 {
		atomic.AddInt32(pendingWork, int32(len(links))) // Add new work
		for _, link := range links {
			if len(c.visited) >= c.maxPages {
				close(c.stopCrawl)
				return
			}
			select {
			case urlQueue <- link:
			default:
				atomic.AddInt32(pendingWork, -1) // Decrement if we couldn't queue
			}
		}
	}
	atomic.AddInt32(pendingWork, -1) // Current URL is done
}

// addForms adds forms for a URL if they are unique
func (c *WebCrawler) addForms(url string, forms []FormField) bool {
	if len(forms) == 0 {
		return false
	}

	// Generate signature for these forms
	signature := c.generateFormSignature(forms)

	// Check if we've seen this form signature before
	c.signaturesLock.Lock()
	seen := c.formSignatures[signature]
	if !seen {
		c.formSignatures[signature] = true
	}
	c.signaturesLock.Unlock()

	if seen {
		return false
	}

	c.formsLock.Lock()
	c.forms[url] = forms
	c.formsLock.Unlock()

	if c.config.Verbose {
		log.Printf("Found new unique form at %s with %d fields\n", url, len(forms))
	}

	return true
}

// generateFormSignature creates a unique signature for a set of form fields
func (c *WebCrawler) generateFormSignature(forms []FormField) string {
	var fields []string
	for _, form := range forms {
		fields = append(fields, fmt.Sprintf("%s:%s:%v:%s",
			form.Name, form.Type, form.Required, form.Pattern))
	}
	sort.Strings(fields) // Sort for consistent ordering
	return strings.Join(fields, "|")
}

// extractForms extracts forms from HTML
func (c *WebCrawler) extractForms(node *html.Node) []FormField {
	var forms []FormField

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			// Extract form fields
			var fields []FormField
			var extractFields func(*html.Node)
			extractFields = func(node *html.Node) {
				if node.Type == html.ElementNode {
					switch node.Data {
					case "input", "select", "textarea":
						field := FormField{}
						for _, attr := range node.Attr {
							switch attr.Key {
							case "name":
								field.Name = attr.Val
							case "type":
								field.Type = attr.Val
							case "required":
								field.Required = true
							case "pattern":
								field.Pattern = attr.Val
							}
						}
						if field.Name != "" {
							fields = append(fields, field)
						}
					}
				}
				for c := node.FirstChild; c != nil; c = c.NextSibling {
					extractFields(c)
				}
			}
			extractFields(n)
			forms = append(forms, fields...)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(node)

	return forms
}

// extractLinks extracts links from HTML
func (c *WebCrawler) extractLinks(node *html.Node) []string {
	var links []string

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					link := c.resolveURL(attr.Val)
					if link != "" {
						links = append(links, link)
					}
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(node)

	return links
}

// resolveURL resolves a URL relative to the base URL
func (c *WebCrawler) resolveURL(href string) string {
	relative, err := url.Parse(href)
	if err != nil {
		return ""
	}
	absolute := c.baseURL.ResolveReference(relative)
	return absolute.String()
}

// isSameHost checks if a URL has the same host as the base URL
func (c *WebCrawler) isSameHost(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsed.Host == c.baseURL.Host
}

// isVisited checks if a URL has been visited
func (c *WebCrawler) isVisited(url string) bool {
	c.visitedLock.RLock()
	defer c.visitedLock.RUnlock()
	return c.visited[url]
}

// markVisited marks a URL as visited
func (c *WebCrawler) markVisited(url string) {
	c.visitedLock.Lock()
	defer c.visitedLock.Unlock()
	c.visited[url] = true
}

// GetForms returns all discovered forms
func (c *WebCrawler) GetForms() map[string][]FormField {
	c.formsLock.RLock()
	defer c.formsLock.RUnlock()

	forms := make(map[string][]FormField)
	for url, fields := range c.forms {
		forms[url] = fields
	}
	return forms
}

// GetVisitedURLs returns all visited URLs
func (c *WebCrawler) GetVisitedURLs() []string {
	c.visitedLock.RLock()
	defer c.visitedLock.RUnlock()

	var urls []string
	for url := range c.visited {
		urls = append(urls, url)
	}
	return urls
}
