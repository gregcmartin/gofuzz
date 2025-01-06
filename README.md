# Web Application Fuzzer

A high-performance web application fuzzer written in golang with coverage-guided testing, form crawling, and security testing capabilities.

## Features

### 1. Intelligent Web Crawling
- Concurrent site exploration (up to 100 workers)
- Automatic form discovery
- Pattern recognition
- Host-bound crawling
- Link extraction

### 2. Form Fuzzing
- Grammar-based input generation
- Field type detection
- Pattern validation
- Context-aware fuzzing
- Coverage tracking

### 3. API Testing
- Automatic API endpoint detection
- Parameter type inference
- Edge case generation
- Request/response validation
- JSON structure analysis
- Method-aware fuzzing (GET/POST/PUT/etc.)
- Content-type detection
- Schema inference

### 4. Security Testing
- SQL injection detection
- Cross-site scripting (XSS) testing
- Path traversal checks
- Command injection testing
- Template injection detection

### 5. Mutation Fuzzing
- AFL-style mutation operators
- Coverage-guided mutation selection
- Energy-based input scheduling
- Adaptive mutation rates
- Population management
- Rare coverage prioritization

### 6. Performance Features
- Configurable concurrency (1-100 workers)
- Efficient resource management
- Thread-safe operations
- Memory-optimized corpus
- Synchronized worker pools

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/fuzzer.git
cd fuzzer

# Build the fuzzer
go build -o webfuzzer cmd/webfuzzer/main.go
```

## Usage

### Basic Usage

```bash
# Basic fuzzing
./webfuzzer -url http://example.com/

# Verbose output
./webfuzzer -url http://example.com/ -v
```

### Performance Modes

```bash
# Full Auto Mode (Maximum Performance)
./webfuzzer -url http://example.com/ --full-auto

# High Performance Custom Setup
./webfuzzer -url http://example.com/ -c 75 -n 8000

# Balanced Performance
./webfuzzer -url http://example.com/ -c 30

# Resource-Conscious Mode
./webfuzzer -url http://example.com/ -c 10 -n 1000
```

### Coverage-Guided Testing

```bash
# Grammar Coverage
./webfuzzer -url http://example.com/ --grammar-coverage

# Systematic Coverage
./webfuzzer -url http://example.com/ --systematic

# Context-Aware Coverage
./webfuzzer -url http://example.com/ --duplicate-contexts

# Mutation-Based Coverage
./webfuzzer -url http://example.com/ --mutation-coverage --seed "http://example.com/api/v1"

# AFL-Style Fuzzing
./webfuzzer -url http://example.com/ --mutation-coverage --min-mutations 2 --max-mutations 10
```

### API Testing

```bash
# API Endpoint Detection and Fuzzing
./webfuzzer -url http://example.com/ --api-fuzzing

# API Schema Inference
./webfuzzer -url http://example.com/ --api-schema

# Comprehensive API Testing
./webfuzzer -url http://example.com/ --api-full
```

### Security Testing

```bash
# SQL Injection Testing
./webfuzzer -url http://example.com/ --sql-injection

# Comprehensive Security Scan
./webfuzzer -url http://example.com/ --full-auto
```

## Configuration Options

| Flag | Description | Default | Range |
|------|-------------|---------|--------|
| `-url` | Target URL to fuzz | Required | - |
| `-c` | Number of concurrent workers | 20 | 1-100 |
| `-n` | Number of requests to send | 2000 | >0 |
| `-t` | Timeout per request | 10s | >1s |
| `-o` | Output directory | ./results | - |
| `-v` | Verbose logging | false | - |
| `--coverage` | Coverage-guided fuzzing | true | - |
| `--grammar-coverage` | Grammar-coverage-guided fuzzing | true | - |
| `--systematic` | Systematic coverage-guided fuzzing | false | - |
| `--max-corpus` | Maximum corpus size | 2000 | >0 |
| `--max-depth` | Maximum grammar tree depth | 10 | >0 |
| `--duplicate-contexts` | Context duplication | false | - |
| `--api-fuzzing` | Enable API fuzzing | false | - |
| `--api-schema` | Enable API schema inference | false | - |
| `--api-full` | Full API testing suite | false | - |
| `--sql-injection` | SQL injection testing | false | - |
| `--mutation-coverage` | Enable mutation-based fuzzing | false | - |
| `--min-mutations` | Minimum mutations per input | 2 | >0 |
| `--max-mutations` | Maximum mutations per input | 10 | >0 |
| `--seed` | Initial seed input for mutation | "" | - |
| `--full-auto` | Enable all capabilities | false | - |

## Full Auto Mode

The `--full-auto` flag enables comprehensive testing with optimized settings and intelligent crawling:

### Crawling Strategy
1. **Sequential Crawling Phase**
   - Initial crawl with single thread
   - Optimized for API endpoint detection
   - Better pattern recognition
   - Reduced false positives

2. **Concurrent Crawling Phase**
   - Broad coverage with multiple workers
   - Form detection and validation
   - Resource discovery
   - Results merged with sequential phase

### Optimized Settings
- 50 concurrent workers
- 10,000 test requests
- 5,000 corpus size
- 30-second timeout

### Enabled Features
- Grammar coverage
- Systematic coverage
- Context duplication
- API endpoint detection and fuzzing
- API schema inference
- SQL injection testing
- Verbose logging
- Form fuzzing
- Security testing

## Output

Results are saved in the output directory (default: ./results):

```
results/
├── fuzzer.log     # Detailed fuzzing logs
├── results.txt    # Test results and findings
└── coverage/      # Coverage reports
```

## Performance Tips

1. **Concurrency Tuning**:
   - Start with 20 workers for balanced performance
   - Increase up to 50 workers for faster testing
   - Use up to 100 workers for maximum throughput
   - Monitor system resources and adjust accordingly

2. **Resource Optimization**:
   - Adjust corpus size based on available memory
   - Set appropriate timeouts for target response times
   - Use resource-conscious mode for limited environments

3. **Testing Strategy**:
   - Start with basic fuzzing to establish baseline
   - Enable coverage-guided features for thorough testing
   - Use full auto mode for comprehensive security testing
   - Monitor and adjust based on results

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a Pull Request

## License

 
 
This project is licensed under the MIT License - see the LICENSE file for details.
