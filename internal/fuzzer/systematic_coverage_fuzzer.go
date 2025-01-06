package fuzzer

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
)

// SystematicCoverageFuzzer implements systematic coverage-guided fuzzing
type SystematicCoverageFuzzer struct {
	*GrammarCoverageFuzzer
	expansionCache map[string]map[int]map[string]bool // Cache for max expansion coverage
	cacheMutex     sync.RWMutex
}

// NewSystematicCoverageFuzzer creates a new systematic coverage-guided fuzzer
func NewSystematicCoverageFuzzer(config *Config) (*SystematicCoverageFuzzer, error) {
	baseFuzzer, err := NewGrammarCoverageFuzzer(config)
	if err != nil {
		return nil, err
	}

	f := &SystematicCoverageFuzzer{
		GrammarCoverageFuzzer: baseFuzzer,
		expansionCache:        make(map[string]map[int]map[string]bool),
	}

	// Pre-compute expansion coverage for all symbols and depths
	f.precomputeExpansionCoverage()

	return f, nil
}

// precomputeExpansionCoverage computes and caches expansion coverage for all symbols
func (f *SystematicCoverageFuzzer) precomputeExpansionCoverage() {
	maxDepth := f.config.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 10 // Default max depth
	}

	for symbol := range f.grammar {
		f.expansionCache[symbol] = make(map[int]map[string]bool)
		for depth := 0; depth <= maxDepth; depth++ {
			coverage := make(map[string]bool)
			f.computeExpansionCoverage(symbol, depth, coverage)
			f.expansionCache[symbol][depth] = coverage
		}
	}
}

// computeExpansionCoverage recursively computes expansion coverage
func (f *SystematicCoverageFuzzer) computeExpansionCoverage(symbol string, depth int, coverage map[string]bool) {
	if depth < 0 {
		return
	}

	// Add all direct expansions for this symbol
	for _, expansion := range f.grammar[symbol] {
		key := fmt.Sprintf("%s -> %s", symbol, expansion)
		coverage[key] = true

		// Recursively compute coverage for nonterminals in expansion
		if depth > 0 {
			for _, part := range strings.Fields(expansion) {
				if isNonterminal(part) {
					f.computeExpansionCoverage(part, depth-1, coverage)
				}
			}
		}
	}
}

// getMaxExpansionCoverage returns cached expansion coverage
func (f *SystematicCoverageFuzzer) getMaxExpansionCoverage(symbol string, depth int) map[string]bool {
	f.cacheMutex.RLock()
	defer f.cacheMutex.RUnlock()

	if depthMap, ok := f.expansionCache[symbol]; ok {
		if coverage, ok := depthMap[depth]; ok {
			return coverage
		}
	}
	return make(map[string]bool)
}

// chooseExpansion selects an expansion to maximize coverage
func (f *SystematicCoverageFuzzer) chooseExpansion(symbol string, expansions []string) string {
	// Get uncovered expansions at current depth
	uncovered := make([]string, 0)
	currentDepth := f.getCurrentDepth()

	for _, exp := range expansions {
		key := fmt.Sprintf("%s -> %s", symbol, exp)
		if !f.isExpansionCovered(key) {
			// Check if this expansion leads to more uncovered expansions
			coverage := f.getMaxExpansionCoverage(symbol, currentDepth)
			if len(coverage) > 0 {
				uncovered = append(uncovered, exp)
			}
		}
	}

	// If we have uncovered expansions, choose one
	if len(uncovered) > 0 {
		return uncovered[rand.Intn(len(uncovered))]
	}

	// Otherwise choose randomly from all expansions
	return expansions[rand.Intn(len(expansions))]
}

// Run starts the fuzzing process with systematic coverage
func (f *SystematicCoverageFuzzer) Run() error {
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
func (f *SystematicCoverageFuzzer) generateDerivationTree(symbol string, depth int) *DerivationTree {
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

// treeToString converts a derivation tree to its string representation
func (f *SystematicCoverageFuzzer) treeToString(tree *DerivationTree) string {
	if len(tree.Children) == 0 {
		return tree.Value
	}

	var result strings.Builder
	for _, child := range tree.Children {
		result.WriteString(f.treeToString(child))
	}
	return result.String()
}

// getCurrentDepth returns current derivation depth
func (f *SystematicCoverageFuzzer) getCurrentDepth() int {
	return f.config.MaxDepth
}

// isExpansionCovered checks if an expansion has been covered
func (f *SystematicCoverageFuzzer) isExpansionCovered(key string) bool {
	return f.grammarCoverage.HasExpansion(key)
}
