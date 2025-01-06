package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"fuzzer/internal/fuzzer"
)

func main() {
	// Parse command line flags
	config := parseFlags()

	// Create and run fuzzer
	f, err := fuzzer.New(config)
	if err != nil {
		log.Fatalf("Error initializing fuzzer: %v", err)
	}

	if err := f.Run(); err != nil {
		log.Fatalf("Error running fuzzer: %v", err)
	}
}

func parseFlags() *fuzzer.Config {
	// Basic settings
	targetURL := flag.String("url", "", "Target URL to fuzz")
	concurrency := flag.Int("c", 10, "Number of concurrent workers")
	numRequests := flag.Int("n", 1000, "Number of requests to send")
	timeout := flag.Duration("t", 10*time.Second, "Timeout per request")
	wordlist := flag.String("w", "", "Path to wordlist file")
	output := flag.String("o", "./results", "Output directory for results")
	verbose := flag.Bool("v", false, "Enable verbose logging")

	// Coverage settings
	useCoverage := flag.Bool("coverage", true, "Use coverage-guided fuzzing")
	useGrammarCoverage := flag.Bool("grammar-coverage", true, "Use grammar-coverage-guided fuzzing")
	useSystematicCoverage := flag.Bool("systematic", false, "Use systematic coverage-guided fuzzing")
	maxCorpus := flag.Int("max-corpus", 1000, "Maximum size of interesting inputs corpus (0 = unlimited)")

	// Grammar settings
	maxDepth := flag.Int("max-depth", 10, "Maximum depth for grammar derivation trees")
	duplicateContexts := flag.Bool("duplicate-contexts", false, "Duplicate grammar rules for context-specific coverage")

	// Mutation settings
	mutationRate := flag.Float64("mutation-rate", 0.7, "Probability of mutating vs generating new (0.0-1.0)")
	maxMutations := flag.Int("max-mutations", 5, "Maximum mutations per input")
	preserveSessions := flag.Bool("preserve-sessions", true, "Maintain session cookies across requests")

	// Parse flags
	flag.Parse()

	// Validate required flags
	if *targetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: target URL is required")
		flag.Usage()
		os.Exit(1)
	}

	// Create config with parsed values
	return &fuzzer.Config{
		// Basic settings
		TargetURL:    *targetURL,
		Concurrency:  *concurrency,
		NumRequests:  *numRequests,
		Timeout:      *timeout,
		WordlistPath: *wordlist,
		OutputDir:    *output,
		Verbose:      *verbose,

		// Coverage settings
		UseCoverage:        *useCoverage,
		UseGrammarCoverage: *useGrammarCoverage,
		MaxCorpus:          *maxCorpus,

		// Grammar settings
		MaxDepth:          *maxDepth,
		UseSystematic:     *useSystematicCoverage,
		DuplicateContexts: *duplicateContexts,

		// Mutation settings
		MutationRate:     *mutationRate,
		MaxMutations:     *maxMutations,
		PreserveSessions: *preserveSessions,
	}
}

func init() {
	// Customize usage output
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] \n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "A web application fuzzer with coverage-guided fuzzing capabilities.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  Basic fuzzing:")
		fmt.Fprintln(os.Stderr, "    fuzzer -url http://example.com/api/")
		fmt.Fprintln(os.Stderr, "\n  Grammar-coverage-guided fuzzing with custom wordlist:")
		fmt.Fprintln(os.Stderr, "    fuzzer -url http://example.com/api/ -w wordlists/web-attacks.txt -c 20 --grammar-coverage")

		fmt.Fprintln(os.Stderr, "\n  Systematic coverage-guided fuzzing:")
		fmt.Fprintln(os.Stderr, "    fuzzer -url http://example.com/api/ --systematic --duplicate-contexts")

		fmt.Fprintln(os.Stderr, "\n  Basic coverage-guided fuzzing:")
		fmt.Fprintln(os.Stderr, "    fuzzer -url http://example.com/api/ --coverage --no-grammar-coverage")
		fmt.Fprintln(os.Stderr, "\n  Intensive fuzzing with more requests:")
		fmt.Fprintln(os.Stderr, "    fuzzer -url http://example.com/api/ -n 5000 -t 15s")
	}
}
