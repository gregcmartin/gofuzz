package fuzzer

import (
	"sync"
)

// GrammarCoverage tracks coverage of grammar expansions
type GrammarCoverage struct {
	// Map of expansion keys to coverage count
	covered map[string]int

	// Map of symbol to its expansions
	expansions map[string][]string

	// Track derivation trees
	trees map[string]bool

	// Track expansion priorities
	priorities map[string]float64

	// Protect concurrent access
	mu sync.RWMutex
}

// NewGrammarCoverage creates a new grammar coverage tracker
func NewGrammarCoverage(grammar Grammar) *GrammarCoverage {
	gc := &GrammarCoverage{
		covered:    make(map[string]int),
		expansions: make(map[string][]string),
		trees:      make(map[string]bool),
		priorities: make(map[string]float64),
	}

	// Initialize expansions map
	for symbol, exps := range grammar {
		gc.expansions[symbol] = make([]string, len(exps))
		copy(gc.expansions[symbol], exps)
	}

	return gc
}

// TrackDerivationTree records a derivation tree and its expansions
func (gc *GrammarCoverage) TrackDerivationTree(tree *DerivationTree) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	// Track tree
	treeStr := tree.ToString()
	gc.trees[treeStr] = true

	// Track all expansions in the tree
	for _, exp := range tree.GetAllExpansions() {
		gc.covered[exp]++
	}

	// Update priorities based on usage
	gc.updatePriorities()
}

// TrackExpansion records an expansion
func (gc *GrammarCoverage) TrackExpansion(symbol, expansion string) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	key := expansionKey(symbol, expansion)
	gc.covered[key]++
	gc.updatePriorities()
}

// GetCoveragePriority returns priority score for an expansion
func (gc *GrammarCoverage) GetCoveragePriority(symbol, expansion string) float64 {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	key := expansionKey(symbol, expansion)
	if priority, ok := gc.priorities[key]; ok {
		return priority
	}
	return 1.0 // Highest priority for uncovered expansions
}

// HasFullCoverage checks if all expansions are covered
func (gc *GrammarCoverage) HasFullCoverage() bool {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	for symbol, exps := range gc.expansions {
		for _, exp := range exps {
			key := expansionKey(symbol, exp)
			if gc.covered[key] == 0 {
				return false
			}
		}
	}
	return true
}

// updatePriorities updates expansion priorities based on coverage
func (gc *GrammarCoverage) updatePriorities() {
	// Calculate total coverage for each symbol
	symbolCoverage := make(map[string]int)
	for key, count := range gc.covered {
		symbol, _ := parseExpansionKey(key)
		symbolCoverage[symbol] += count
	}

	// Update priorities
	gc.priorities = make(map[string]float64)
	for symbol, exps := range gc.expansions {
		total := symbolCoverage[symbol]
		if total == 0 {
			total = 1
		}
		for _, exp := range exps {
			key := expansionKey(symbol, exp)
			count := gc.covered[key]
			if count == 0 {
				gc.priorities[key] = 1.0 // Highest priority
			} else {
				gc.priorities[key] = 1.0 - (float64(count) / float64(total))
			}
		}
	}
}

// HasExpansion checks if an expansion has been covered
func (gc *GrammarCoverage) HasExpansion(key string) bool {
	gc.mu.RLock()
	defer gc.mu.RUnlock()
	return gc.covered[key] > 0
}

// AddExpansion records coverage of an expansion
func (gc *GrammarCoverage) AddExpansion(symbol, expansion string) {
	key := expansionKey(symbol, expansion)
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.covered[key]++
}

// GetCoverage returns the current coverage count for an expansion
func (gc *GrammarCoverage) GetCoverage(key string) int {
	gc.mu.RLock()
	defer gc.mu.RUnlock()
	return gc.covered[key]
}

// GetUncoveredExpansions returns expansions not yet covered
func (gc *GrammarCoverage) GetUncoveredExpansions(grammar Grammar) []string {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	var uncovered []string
	for symbol, exps := range grammar {
		for _, exp := range exps {
			key := expansionKey(symbol, exp)
			if gc.covered[key] == 0 {
				uncovered = append(uncovered, key)
			}
		}
	}
	return uncovered
}

// GetCoverageStats returns coverage statistics
func (gc *GrammarCoverage) GetCoverageStats() map[string]interface{} {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	stats := make(map[string]interface{})

	// Total expansions and covered count
	total := 0
	covered := 0
	for symbol, exps := range gc.expansions {
		for _, exp := range exps {
			total++
			key := expansionKey(symbol, exp)
			if gc.covered[key] > 0 {
				covered++
			}
		}
	}

	stats["total_expansions"] = total
	stats["covered_expansions"] = covered
	if total > 0 {
		stats["coverage_percentage"] = float64(covered) / float64(total) * 100
	} else {
		stats["coverage_percentage"] = 0.0
	}

	// Coverage by symbol
	symbolStats := make(map[string]interface{})
	for symbol, exps := range gc.expansions {
		symbolTotal := len(exps)
		symbolCovered := 0
		for _, exp := range exps {
			key := expansionKey(symbol, exp)
			if gc.covered[key] > 0 {
				symbolCovered++
			}
		}
		symbolStats[symbol] = map[string]interface{}{
			"total":      symbolTotal,
			"covered":    symbolCovered,
			"percentage": float64(symbolCovered) / float64(symbolTotal) * 100,
		}
	}
	stats["by_symbol"] = symbolStats

	return stats
}

// Reset clears all coverage data
func (gc *GrammarCoverage) Reset() {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.covered = make(map[string]int)
}

// GetAllExpansions returns all possible expansions
func (gc *GrammarCoverage) GetAllExpansions() []string {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	var all []string
	for symbol, exps := range gc.expansions {
		for _, exp := range exps {
			all = append(all, expansionKey(symbol, exp))
		}
	}
	return all
}

// GetCoveredExpansions returns all covered expansions
func (gc *GrammarCoverage) GetCoveredExpansions() []string {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	var covered []string
	for key, count := range gc.covered {
		if count > 0 {
			covered = append(covered, key)
		}
	}
	return covered
}

// GetExpansionCount returns total number of expansions
func (gc *GrammarCoverage) GetExpansionCount() int {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	count := 0
	for _, exps := range gc.expansions {
		count += len(exps)
	}
	return count
}

// GetCoveredCount returns number of covered expansions
func (gc *GrammarCoverage) GetCoveredCount() int {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	count := 0
	for _, c := range gc.covered {
		if c > 0 {
			count++
		}
	}
	return count
}
