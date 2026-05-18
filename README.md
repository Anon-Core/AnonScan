# AnonScan

A systematic web vulnerability scanner designed for security professionals and penetration testers.

## Features

- **Comprehensive Scanning**: Detect common web vulnerabilities including SQL Injection, XSS, and CSRF
- **Fast & Efficient**: Optimized scanning engine for large-scale assessments
- **Detailed Reports**: Generate detailed vulnerability reports with remediation guidance
- **Multiple Output Formats**: Support for JSON, HTML, and CSV export
- **Customizable Payloads**: Create and manage custom exploit payloads
- **Session Management**: Persistent session handling for authenticated scanning

## Installation

### Requirements
- Python 3.8+
- pip

### Setup

```bash
git clone https://github.com/Anon-Core/AnonScan.git
cd AnonScan
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python anonscan.py -u https://target.com
```

### Advanced Scan with Options
```bash
python anonscan.py -u https://target.com \
    --threads 10 \
    --timeout 30 \
    --output report.json \
    --level 2
```

### Command Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL (required) |
| `--threads` | Number of concurrent threads (default: 5) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--output` | Output file path |
| `--level` | Scan intensity: 1=basic, 2=moderate, 3=aggressive |
| `--auth` | Basic authentication credentials |
| `--proxy` | HTTP proxy URL |

## Project Structure

```
AnonScan/
├── anonscan.py          # Main application
├── scanner/
│   ├── __init__.py
│   ├── core.py          # Core scanning logic
│   ├── payloads.py      # Exploit payloads
│   └── parser.py        # Response parser
├── reports/
│   ├── generator.py     # Report generation
│   └── templates/       # Report templates
├── config/
│   └── settings.py      # Configuration
├── requirements.txt
└── README.md
```

## Security & Disclaimer

This tool is designed for authorized security testing only. Unauthorized access to computer systems is illegal. Users are responsible for ensuring they have proper authorization before scanning any targets. The authors assume no liability for misuse.

## Contributing

Contributions are welcome. Please follow these guidelines:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Submit a pull request

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Contact

For questions or support, reach out to the Anon Security team.

---

**Status**: Active Development  
**Last Updated**: May 2026
