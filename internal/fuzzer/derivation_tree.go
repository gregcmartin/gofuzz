package fuzzer

import (
	"fmt"
	"strings"
)

// DerivationTree represents a node in the grammar derivation tree
type DerivationTree struct {
	Symbol    string            // The grammar symbol at this node
	Children  []*DerivationTree // Child nodes
	Value     string            // The final string value (for terminals)
	Expansion string            // The expansion used for this node
}

// NewDerivationTree creates a new derivation tree node
func NewDerivationTree(symbol string) *DerivationTree {
	return &DerivationTree{
		Symbol:   symbol,
		Children: make([]*DerivationTree, 0),
	}
}

// AddChild adds a child node to this tree
func (t *DerivationTree) AddChild(child *DerivationTree) {
	t.Children = append(t.Children, child)
}

// ToString converts the tree to a string representation
func (t *DerivationTree) ToString() string {
	if len(t.Children) == 0 {
		if t.Value != "" {
			return t.Value
		}
		return t.Symbol
	}

	var childStrs []string
	for _, child := range t.Children {
		childStrs = append(childStrs, child.ToString())
	}
	return fmt.Sprintf("(%s %s)", t.Symbol, strings.Join(childStrs, " "))
}

// GetAllExpansions returns all expansions used in this tree
func (t *DerivationTree) GetAllExpansions() []string {
	var expansions []string
	if t.Expansion != "" {
		expansions = append(expansions, expansionKey(t.Symbol, t.Expansion))
	}
	for _, child := range t.Children {
		expansions = append(expansions, child.GetAllExpansions()...)
	}
	return expansions
}

// GetDepth returns the maximum depth of the tree
func (t *DerivationTree) GetDepth() int {
	if len(t.Children) == 0 {
		return 0
	}

	maxChildDepth := 0
	for _, child := range t.Children {
		childDepth := child.GetDepth()
		if childDepth > maxChildDepth {
			maxChildDepth = childDepth
		}
	}
	return maxChildDepth + 1
}

// GetSymbols returns all symbols used in this tree
func (t *DerivationTree) GetSymbols() []string {
	symbols := []string{t.Symbol}
	for _, child := range t.Children {
		symbols = append(symbols, child.GetSymbols()...)
	}
	return symbols
}

// Clone creates a deep copy of the tree
func (t *DerivationTree) Clone() *DerivationTree {
	clone := &DerivationTree{
		Symbol:    t.Symbol,
		Value:     t.Value,
		Expansion: t.Expansion,
		Children:  make([]*DerivationTree, len(t.Children)),
	}
	for i, child := range t.Children {
		clone.Children[i] = child.Clone()
	}
	return clone
}

// GetLeafValues returns all leaf node values in order
func (t *DerivationTree) GetLeafValues() []string {
	if len(t.Children) == 0 {
		if t.Value != "" {
			return []string{t.Value}
		}
		return []string{t.Symbol}
	}

	var values []string
	for _, child := range t.Children {
		values = append(values, child.GetLeafValues()...)
	}
	return values
}

// GetSubtrees returns all subtrees (including this tree)
func (t *DerivationTree) GetSubtrees() []*DerivationTree {
	trees := []*DerivationTree{t}
	for _, child := range t.Children {
		trees = append(trees, child.GetSubtrees()...)
	}
	return trees
}

// GetPatterns returns all recurring patterns in the tree
func (t *DerivationTree) GetPatterns() []string {
	patterns := make(map[string]bool)
	subtrees := t.GetSubtrees()

	// Get string representation of each subtree
	for _, subtree := range subtrees {
		str := subtree.ToString()
		if len(str) >= 2 { // Only consider patterns of length 2 or more
			patterns[str] = true
		}
	}

	// Convert to slice
	var result []string
	for pattern := range patterns {
		result = append(result, pattern)
	}
	return result
}
