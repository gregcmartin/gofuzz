package fuzzer

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// GrammarCoverageFuzzer implements coverage-guided fuzzing
type GrammarCoverageFuzzer struct {
	*CoverageFuzzer
	grammar         Grammar
	grammarCoverage *GrammarCoverage
}

// NewGrammarCoverageFuzzer creates a new grammar-coverage-guided fuzzer
func NewGrammarCoverageFuzzer(config *Config) (*GrammarCoverageFuzzer, error) {
	baseFuzzer, err := NewCoverageFuzzer(config)
	if err != nil {
		return nil, err
	}

	// Initialize grammar coverage
	grammar := make(Grammar)
	for symbol, expansions := range baseFuzzer.grammar {
		grammar[symbol] = make([]string, len(expansions))
		copy(grammar[symbol], expansions)
	}

	return &GrammarCoverageFuzzer{
		CoverageFuzzer:  baseFuzzer,
		grammar:         grammar,
		grammarCoverage: NewGrammarCoverage(grammar),
	}, nil
}

// Run starts the fuzzing process with grammar coverage guidance
func (f *GrammarCoverageFuzzer) Run() error {
	// Create derivation tree
	tree := f.generateDerivationTree("<start>", 0)

	// Track coverage
	f.grammarCoverage.TrackDerivationTree(tree)

	// Convert tree to string and test it
	input := f.treeToString(tree)
	result := f.testInput(input)

	// Process result
	if result.Error != nil {
		if f.config.Verbose {
			fmt.Printf("[ERROR] %s: %v\n", result.URL, result.Error)
		}
		return result.Error
	}

	if f.config.Verbose {
		fmt.Printf("[%d] %s\n", result.StatusCode, result.URL)
	}

	return nil
}

// generateDerivationTree creates a derivation tree for a symbol
func (f *GrammarCoverageFuzzer) generateDerivationTree(symbol string, depth int) *DerivationTree {
	if depth > f.config.MaxDepth {
		return &DerivationTree{
			Symbol: symbol,
			Value:  "max_depth_reached",
		}
	}

	tree := NewDerivationTree(symbol)

	// Get possible expansions
	expansions := f.grammar[symbol]
	if len(expansions) == 0 {
		// Terminal symbol
		tree.Value = symbol
		return tree
	}

	// Choose expansion based on coverage
	expansion := f.chooseExpansion(symbol, expansions)
	tree.Expansion = expansion

	// Track expansion
	f.grammarCoverage.TrackExpansion(symbol, expansion)

	// Generate children
	parts := strings.Fields(expansion)
	for _, part := range parts {
		if isNonterminal(part) {
			child := f.generateDerivationTree(part, depth+1)
			tree.AddChild(child)
		} else {
			child := &DerivationTree{
				Symbol: part,
				Value:  part,
			}
			tree.AddChild(child)
		}
	}

	return tree
}

// chooseExpansion selects an expansion based on coverage
func (f *GrammarCoverageFuzzer) chooseExpansion(symbol string, expansions []string) string {
	// Get priorities for each expansion
	priorities := make([]float64, len(expansions))
	totalPriority := 0.0

	for i, exp := range expansions {
		priority := f.grammarCoverage.GetCoveragePriority(symbol, exp)
		priorities[i] = priority
		totalPriority += priority
	}

	// Choose based on weighted probability
	if totalPriority > 0 {
		r := rand.Float64() * totalPriority
		sum := 0.0
		for i, priority := range priorities {
			sum += priority
			if r <= sum {
				return expansions[i]
			}
		}
	}

	// Fallback to random selection
	return expansions[rand.Intn(len(expansions))]
}

// treeToString converts a derivation tree to its string representation
func (f *GrammarCoverageFuzzer) treeToString(tree *DerivationTree) string {
	if len(tree.Children) == 0 {
		return tree.Value
	}

	var result strings.Builder
	for _, child := range tree.Children {
		result.WriteString(f.treeToString(child))
	}
	return result.String()
}

// GetCoverageStats returns current coverage statistics
func (f *GrammarCoverageFuzzer) GetCoverageStats() map[string]interface{} {
	return f.grammarCoverage.GetCoverageStats()
}

// Reset clears coverage data
func (f *GrammarCoverageFuzzer) Reset() {
	f.grammarCoverage.Reset()
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
