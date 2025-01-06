package fuzzer

// FuzzerInterface defines the common interface for all fuzzer implementations
type FuzzerInterface interface {
	// Run starts the fuzzing process
	Run() error
}
