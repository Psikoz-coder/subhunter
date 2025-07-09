# Subhunter

```
   ███████╗██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
   ██╔════╝██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   ███████╗██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ╚════██║██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
   ███████║╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

                   Advanced Subdomain Enumeration Tool
                               by: Psikoz
```

A powerful subdomain enumeration tool that combines multiple data sources for comprehensive subdomain discovery. Subhunter is designed for security professionals and bug bounty hunters to perform thorough reconnaissance.

## 🌟 Features

- 🔍 **Multi-Source Enumeration** - Combines results from multiple public sources
- 🚀 **High Performance** - Concurrent scanning with configurable threads
- 📊 **Comparison Mode** - Compare results with other tools like Subfinder
- 📁 **Flexible Output** - Save results to file with customizable naming
- 📈 **Detailed Reporting** - Get statistics and detailed comparison reports
- 🔄 **Smart Deduplication** - Automatic removal of duplicate entries
- 🛡️ **Respectful Scanning** - Built-in delays and rate limiting

## 📦 Installation

### Prerequisites
- Go 1.16 or higher
- Internet connection

### Install with go install
```bash
# Install the specific version
go install github.com/Psikoz-coder/subhunter@v0.1.0

# Make sure your Go bin directory is in your PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# Verify installation
subhunter --help
```

### Install from Source
```bash
git clone https://github.com/Psikoz-coder/subhunter.git
cd subhunter
go build -o subhunter
sudo mv subhunter /usr/local/bin/
```

### Docker Installation
```bash
# Pull the latest image
docker pull ghcr.io/psikoz-coder/subhunter:latest

# Run the container
docker run -it --rm ghcr.io/psikoz-coder/subhunter -d example.com
```

### Update to Latest Version
```bash
go install github.com/Psikoz-coder/subhunter@v0.1.0
```

## 🚀 Quick Start

### Basic Usage
```bash
# Scan a single domain
subhunter -d example.com

# Save results to a file
subhunter -d example.com -o results.txt

# Enable verbose output
subhunter -d example.com -v

# Compare with Subfinder results
subhunter -d example.com --compare subfinder_results.txt
```

## 🛠️ Usage

```
Usage: subhunter -d <domain> [options]

Required Flags:
  -d, --domain string    Target domain to scan

Optional Flags:
  -o, --output string    Output file (default: subhunter_<domain>_<timestamp>.txt)
  -v, --verbose          Enable verbose output
  -t, --threads int      Number of concurrent threads (default 5)
      --timeout int      HTTP request timeout in seconds (default 30)
      --compare string   Compare with subdomains from another tool's output file
  -c, --check            Run system check before scanning
  -h, --help             Show this help message
```

## 🔄 Comparison Mode

Subhunter can compare its results with other tools like Subfinder to identify unique and common subdomains:

```bash
# First run Subfinder
subfinder -d example.com -o subfinder_results.txt

# Then compare with Subhunter
subhunter -d example.com --compare subfinder_results.txt -v
```

This will generate several files:
- `subhunter_only_<domain>_<timestamp>.txt` - Unique to Subhunter
- `subfinder_only_<domain>_<timestamp>.txt` - Unique to the compared file
- `common_<domain>_<timestamp>.txt` - Found by both tools
- `comparison_summary_<domain>_<timestamp>.txt` - Summary report

## 📊 Example Output

```
[+] Target:        example.com
[+] Output:        subhunter_example_com_20250709_1337.txt
[+] Threads:       5
[+] Timeout:       30 seconds
[+] Start Time:    2025-07-09 13:37:45

[*] Scanning RapidDNS...
[*] Scanning Riddler...
[*] Scanning JLDC Anubis...
[*] Scanning crt.sh...
[*] Scanning BufferOver...
[*] Scanning URLScan...
[+] Merging and cleaning results...

[+] Comparison Results:
[+] SubHunter found: 42 subdomains
[+] Other tool found: 37 subdomains
[+] Unique to SubHunter: 8
[+] Unique to other tool: 3
[+] Common subdomains: 34

[+] Scan completed in 12.45 seconds
[+] Found 42 unique subdomains
[+] Results saved to: subhunter_example_com_20250709_1337.txt
[+] Comparison results saved to files with timestamp: 20250709_133745
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

This tool is intended for security testing and research purposes only. Only use on targets you own or have explicit permission to test. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 📧 Contact

For questions or feedback, please open an issue on GitHub.

---

⭐ **If you find this tool useful, please give it a star!**

🐛 **Found a bug?** [Open an issue](https://github.com/Psikoz-coder/subhunter/issues)

💡 **Have a feature request?** [Start a discussion](https://github.com/Psikoz-coder/subhunter/discussions)
