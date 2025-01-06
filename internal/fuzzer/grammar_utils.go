package fuzzer

import (
	"strings"
)

// isNonterminal checks if a string is a nonterminal symbol (enclosed in < >)
func isNonterminal(s string) bool {
	return strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">")
}

// Grammar represents a context-free grammar
type Grammar map[string][]string

// expansionKey creates a unique key for a symbol and its expansion
func expansionKey(symbol, expansion string) string {
	return symbol + " -> " + expansion
}

// parseExpansionKey parses a symbol and expansion from an expansion key
func parseExpansionKey(key string) (symbol, expansion string) {
	parts := strings.SplitN(key, " -> ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
