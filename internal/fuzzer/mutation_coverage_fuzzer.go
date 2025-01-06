package fuzzer

import (
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"sync"
)

// MutationCoverageFuzzer implements coverage-guided mutation fuzzing
type MutationCoverageFuzzer struct {
	*MutationFuzzer
	population    []string        // Current population of inputs
	coverageSeen  map[string]bool // Track unique coverage paths
	coverageLock  sync.RWMutex    // Protect coverage map
	energies      map[string]int  // Energy assigned to each input
	totalEnergy   int             // Total energy in the system
	maxPopulation int             // Maximum population size
}

// NewMutationCoverageFuzzer creates a new coverage-guided mutation fuzzer
func NewMutationCoverageFuzzer(config *Config) (*MutationCoverageFuzzer, error) {
	base, err := NewMutationFuzzer(config)
	if err != nil {
		return nil, err
	}

	return &MutationCoverageFuzzer{
		MutationFuzzer: base,
		population:     make([]string, 0),
		coverageSeen:   make(map[string]bool),
		energies:       make(map[string]int),
		maxPopulation:  config.MaxCorpus,
	}, nil
}

// Run starts the coverage-guided fuzzing process
func (f *MutationCoverageFuzzer) Run() error {
	// Initialize population with seed inputs
	for _, seed := range f.config.SeedInputs {
		f.addToPopulation(seed)
	}

	// Main fuzzing loop
	for i := 0; i < f.config.NumRequests; i++ {
		// Select input based on energy
		input := f.selectInput()

		// Generate mutations
		numMutations := f.config.MinMutations
		if f.config.MaxMutations > f.config.MinMutations {
			numMutations += rand.Intn(f.config.MaxMutations - f.config.MinMutations + 1)
		}

		mutated := input
		for j := 0; j < numMutations; j++ {
			mutated = f.mutate(mutated)
		}

		// Test the mutated input
		resp, err := f.test(mutated)
		if err != nil {
			if f.config.Verbose {
				fmt.Printf("Error testing %s: %v\n", mutated, err)
			}
			continue
		}

		// Calculate coverage
		coverage := f.calculateCoverage(resp)

		// Check if we found new coverage
		if f.isNewCoverage(coverage) {
			if f.config.Verbose {
				fmt.Printf("New coverage found: %s\n", mutated)
			}
			f.addToPopulation(mutated)
			f.assignEnergy(mutated, 10) // High energy for new coverage
		} else {
			f.assignEnergy(input, 1) // Low energy for existing coverage
		}

		// Maintain population size
		f.prunePopulation()
	}

	return nil
}

// addToPopulation adds a new input to the population
func (f *MutationCoverageFuzzer) addToPopulation(input string) {
	f.population = append(f.population, input)
	f.energies[input] = 1
	f.totalEnergy++
}

// selectInput selects an input from the population based on energy
func (f *MutationCoverageFuzzer) selectInput() string {
	if len(f.population) == 0 {
		return f.config.SeedInputs[0]
	}

	// Roulette wheel selection
	point := rand.Intn(f.totalEnergy)
	sum := 0
	for _, input := range f.population {
		sum += f.energies[input]
		if sum > point {
			return input
		}
	}

	return f.population[len(f.population)-1]
}

// calculateCoverage calculates coverage information from a response
func (f *MutationCoverageFuzzer) calculateCoverage(resp *http.Response) string {
	// Simple coverage metric based on status code and response size
	return fmt.Sprintf("%d-%d", resp.StatusCode, resp.ContentLength)
}

// isNewCoverage checks if we've seen this coverage before
func (f *MutationCoverageFuzzer) isNewCoverage(coverage string) bool {
	f.coverageLock.Lock()
	defer f.coverageLock.Unlock()

	if !f.coverageSeen[coverage] {
		f.coverageSeen[coverage] = true
		return true
	}
	return false
}

// assignEnergy assigns energy to an input
func (f *MutationCoverageFuzzer) assignEnergy(input string, energy int) {
	oldEnergy := f.energies[input]
	f.energies[input] = energy
	f.totalEnergy = f.totalEnergy - oldEnergy + energy
}

// prunePopulation maintains the population size
func (f *MutationCoverageFuzzer) prunePopulation() {
	if len(f.population) <= f.maxPopulation {
		return
	}

	// Sort inputs by energy
	type inputEnergy struct {
		input  string
		energy int
	}
	var entries []inputEnergy
	for _, input := range f.population {
		entries = append(entries, inputEnergy{input, f.energies[input]})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].energy > entries[j].energy
	})

	// Keep only the highest energy inputs
	f.population = make([]string, 0, f.maxPopulation)
	f.totalEnergy = 0
	for i := 0; i < f.maxPopulation && i < len(entries); i++ {
		f.population = append(f.population, entries[i].input)
		f.totalEnergy += entries[i].energy
	}

	// Clean up energies map
	newEnergies := make(map[string]int)
	for _, input := range f.population {
		newEnergies[input] = f.energies[input]
	}
	f.energies = newEnergies
}
