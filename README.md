# Web Application Fuzzer

A comprehensive web application fuzzer written in golang with coverage-guided mutation capabilities, concurrent crawling, and intelligent form detection.

## Features

### Web Crawling
- Concurrent and sequential crawling modes
- Intelligent form detection
- JavaScript form detection
- API endpoint detection
- Security protection detection

### Fuzzing Capabilities
- Coverage-guided mutation fuzzing
- Form-based fuzzing
- SQL injection testing
- API endpoint fuzzing
- Grammar-based fuzzing

### Mutation Strategies
- Path component mutations
- Query parameter mutations
- Special character injections
- Path traversal attempts
- Command injection payloads

### Coverage Analysis
- Response code coverage
- Response size coverage
- Header coverage
- Energy-based input scheduling
- Population pruning for efficiency

## Installation

```bash
# Clone the repository
git clone https://github.com/gregcmartin/fuzzer.git
cd fuzzer

# Build the project
go build -o webfuzzer cmd/webfuzzer/main.go
```

## Usage

### Basic Fuzzing
```bash
# Basic website fuzzing
webfuzzer -url http://example.com/
```

### Mutation-based Fuzzing
```bash
# Coverage-guided mutation fuzzing
webfuzzer -url http://example.com/ --mutation-coverage --seed "http://example.com/api/v1" --min-mutations 2 --max-mutations 10
```

### API Fuzzing
```bash
# API endpoint detection and fuzzing
webfuzzer -url http://example.com/ --api-fuzzing -v

# Full API testing suite
webfuzzer -url http://example.com/ --api-full
```

### SQL Injection Testing
```bash
# SQL injection testing with verbose output
webfuzzer -url http://example.com/ --sql-injection -v
```

### Full Automatic Testing
```bash
# Enable all testing capabilities
webfuzzer -url http://example.com/ --full-auto
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-url` | Target URL to fuzz | (required) |
| `-c` | Number of concurrent workers | 10 |
| `-n` | Number of requests to send | 1000 |
| `-t` | Timeout per request | 10s |
| `-o` | Output directory for results | ./results |
| `-v` | Enable verbose logging | false |
| `--mutation-coverage` | Enable mutation-based fuzzing | false |
| `--seed` | Initial seed input for mutation | "" |
| `--min-mutations` | Minimum mutations per input | 2 |
| `--max-mutations` | Maximum mutations per input | 10 |
| `--api-fuzzing` | Enable API endpoint detection | false |
| `--sql-injection` | Enable SQL injection testing | false |
| `--full-auto` | Enable all testing capabilities | false |

## Architecture

### Core Components
- **Web Crawler**: Concurrent crawler with form detection
- **Mutation Fuzzer**: Base mutation fuzzing implementation
- **Coverage Fuzzer**: Coverage-guided fuzzing with energy scheduling
- **Form Fuzzer**: Intelligent form field fuzzing
- **API Detector**: API endpoint detection and schema inference
- **Security Detector**: Security protection detection

### Project Structure
```
.
├── cmd/
│   └── webfuzzer/
│       └── main.go
├── internal/
│   └── fuzzer/
│       ├── web_crawler.go
│       ├── mutation_fuzzer.go
│       ├── mutation_coverage_fuzzer.go
│       ├── form.go
│       ├── api_detector.go
│       └── sql_injection_fuzzer.go
├── wordlists/
│   └── web-attacks.txt
├── go.mod
├── go.sum
└── README.md
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Considerations

This tool is intended for security testing of your own systems or systems you have permission to test. Do not use this tool against systems you don't own or have explicit permission to test.

## Acknowledgments

- Inspired by modern fuzzing techniques from AFL and libFuzzer
- Uses coverage-guided fuzzing principles for efficient testing
- Implements concurrent crawling patterns for better performance
