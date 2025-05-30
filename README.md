# DotSeek

**DotSeek** is a powerful command-line tool for checking domain availability using the Namecheap API. It provides intelligent caching, TLD filtering, batch processing capabilities, and flexible export options to help you find the perfect domain name efficiently.

## Features

- **Fast Domain Checking**: Batch API calls with intelligent caching
- **TLD Filtering**: Filter by length, keywords, or custom criteria  
- **Premium Detection**: Identify premium domains with pricing indicators
- **Smart Caching**: Configurable cache with automatic expiration
- **Colored Output**: Easy-to-read results with color-coded availability
- **Multiple Export Formats**: Export results to JSON, XML, YAML, TOML, or CSV
- **Multiple TLD Sources**: Remote URL, local file, or embedded TLD lists
- **Sandbox Support**: Test with Namecheap's sandbox environment
- **TLD Descriptions**: Optional keyword descriptions for TLD context

## Installation

### Prerequisites

- Go 1.19 or higher
- Namecheap API account with API access enabled

### Build from Source

```bash
git clone https://github.com/samsonzone/dotseek.git
cd dotseek
go mod tidy
go build -o dotseek
```

### Install Globally

```bash
go install
```

## Configuration

### Required Environment Variables

Create a `.env` file in your working directory or set these environment variables:

```bash
NAMECHEAP_API_USER=your_api_username
NAMECHEAP_API_KEY=your_api_key  
NAMECHEAP_USERNAME=your_account_username
NAMECHEAP_CLIENT_IP=your_whitelisted_ip
```

### Optional Environment Variables

```bash
NAMECHEAP_USE_SANDBOX=true  # Use sandbox environment for testing
```

### Getting Namecheap API Credentials

1. Log into your Namecheap account
2. Go to Profile → Tools → Namecheap API
3. Enable API access and whitelist your IP address
4. Generate your API key and note your API username

## Usage

### Basic Usage

Check specific domains:
```bash
dotseek example.com google.org
```

Check base domain against multiple TLDs:
```bash
dotseek myapp
```

Using the domains flag:
```bash
dotseek -domains="example.com,myapp.io,testsite"
```

### TLD Filtering

Filter by TLD length:
```bash
dotseek -l 3 myapp          # Only 3-character TLDs (.com, .net, .org)
dotseek -l "<4" myapp       # TLDs shorter than 4 characters  
dotseek -l ">=5" myapp      # TLDs 5 characters or longer
```

Filter by keywords:
```bash
dotseek -k "tech,business" myapp     # Include tech/business TLDs
dotseek -ek "adult,gambling" myapp   # Exclude adult/gambling TLDs
```

### Display Options

Show all domains (available and unavailable):
```bash
dotseek -a myapp
```

Include premium domains in results:
```bash
dotseek -p myapp
```

Show TLD descriptions:
```bash
dotseek -d myapp
# or
dotseek -tld-descriptions myapp
```

### Export Options

Export results to various formats:

```bash
# Export to JSON (format inferred from extension)
dotseek -o results.json myapp

# Export to CSV
dotseek -o domains.csv myapp

# Export with explicit format (overrides extension)
dotseek -o myfile.txt -f yaml myapp

# Export using format only (creates default filename)
dotseek -f json myapp  # Creates results.json
```

Supported export formats:
- **JSON**: Structured data with full details
- **XML**: Hierarchical format for system integration
- **YAML**: Human-readable configuration format
- **TOML**: Simple configuration format
- **CSV**: Spreadsheet-compatible format

All export formats include:
- Timestamp of when the check was performed
- Total domains evaluated, available, unavailable, and premium counts
- Complete results for all evaluated domains (not just displayed ones)

### Cache Management

Disable cache for current run:
```bash
dotseek -no-cache myapp
```

Clear cache file:
```bash
dotseek -clear-cache
```

Set custom cache age (in seconds):
```bash
dotseek -cache-age 3600 myapp  # 1 hour
```

### Custom TLD File

Use a custom TLD file instead of the default sources:
```bash
dotseek -tld-file custom_tlds.csv myapp
```

## TLD File Format

TLD files should be in CSV format with the following structure:

```csv
tld,keywords
com,commercial,business,general
org,organization,nonprofit
net,network,internet,tech
dev,development,tech,programming
io,tech,startup,input-output
ai,artificial-intelligence,tech,innovation
```

## TLD Source Priority

DotSeek loads TLD data in the following order (when `--tld-file` is not specified):

1. **Remote URL**: `https://raw.githubusercontent.com/samsonzone/dotseek/refs/heads/main/tlds.txt`
2. **Local File**: `tlds.txt` in current working directory
3. **Embedded List**: Fallback embedded TLD list

## Output Format

### Color Coding

- **Green**: Available domains
- **Red**: Unavailable domains  
- **Yellow**: System messages and sandbox notices

### Premium Indicators

- **$**: Premium domain (higher registration cost)

### Example Output

```
--- Results (15 matching criteria) ---
myapp.com           commercial, business, general
myapp.dev $         development, tech, programming  
myapp.io            tech, startup, input-output
myapp.net           network, internet, tech
myapp.org           organization, nonprofit

Finished. Evaluated 150 domains total.

--- Summary of All Evaluated Domains ---
Available:   5
Unavailable: 145  
Premium:     12
```

## Advanced Examples

### Startup Domain Search
```bash
# Find short, tech-focused domains for a startup
dotseek -l "<=4" -k "tech,startup" -p -d mystartup
```

### E-commerce Domain Search  
```bash
# Find business-appropriate domains, excluding adult content
dotseek -k "business,commercial" -ek "adult,gambling" -a mystore
```

### Developer Portfolio
```bash
# Find developer-focused domains with descriptions
dotseek -k "tech,development,personal" -d johndoe
```

### Comprehensive Domain Research
```bash
# Check everything, show all results with detailed info
dotseek -a -p -d -cache-age 7200 brandname
```

### Domain Research with Export
```bash
# Check domains and export to JSON for analysis
dotseek -k "tech,startup" -o analysis.json mystartup

# Export all results to CSV for spreadsheet analysis
dotseek -a -p -o domains.csv -f csv brandname

# Export only available domains to YAML
dotseek -o available.yaml myapp
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--domains` | | Comma-separated domain names (base or FQDN) |
| `--l` | `-l` | Filter TLDs by length (e.g., '3', '<4', '>=5') |
| `--k` | `-k` | Include TLDs with specified keywords |
| `--ek` | `-ek` | Exclude TLDs with specified keywords |
| `--p` | `-p` | Include premium domains in results |
| `--a` | `-a` | Show all domains (available and unavailable) |
| `--tld-descriptions` | `-d` | Show TLD keyword descriptions |
| `--tld-file` | | Path to custom TLD file |
| `--output` | `-o` | Output to file (format inferred from extension) |
| `--format` | `-f` | Output format (json\|xml\|yaml\|toml\|csv) |
| `--no-cache` | | Disable cache for this run |
| `--clear-cache` | | Clear cache file and exit |
| `--cache-age` | | Maximum cache age in seconds (default: 86400) |

## Caching System

DotSeek uses a JSON-based caching system to minimize API calls and improve performance:

- **Cache File**: `.cache.json` in current working directory
- **Default Age**: 24 hours (86400 seconds)
- **Cache Keys**: Domain names
- **Cached Data**: Availability status, premium status, timestamps

### Cache Benefits

- Reduces API usage and costs
- Faster repeated searches
- Offline capability for previously checked domains
- Configurable expiration

## Error Handling

DotSeek provides comprehensive error handling for:

- **Network Issues**: Timeout and connection errors
- **API Errors**: Namecheap API error responses  
- **Invalid Domains**: Malformed domain name detection
- **Missing Config**: Clear messages for missing credentials
- **File Errors**: TLD file reading and parsing issues
- **Export Errors**: Invalid format or file writing issues

## Rate Limiting

- **Batch Size**: Maximum 50 domains per API call
- **Delay**: 5ms between API calls (configurable in source)
- **Timeout**: 30-second request timeout

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Copyright 2025 Brian Samson <brian@samson.zone>

## Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: Check the embedded help with `dotseek --help`
- **API Documentation**: [Namecheap API Docs](https://www.namecheap.com/support/api/)

## Troubleshooting

### Common Issues

**"Missing required environment variables"**
- Ensure all required environment variables are set in `.env` file or system environment

**"API Error: Invalid IP"**  
- Verify your IP address is whitelisted in Namecheap API settings
- Check that `NAMECHEAP_CLIENT_IP` matches your actual IP

**"No TLDs loaded"**
- Check internet connectivity for remote TLD fetching
- Verify local `tlds.txt` file format if using local file
- Ensure embedded TLD list is present in binary

**"Cannot infer format from filename"**
- Use the `-f` flag to explicitly specify the output format
- Or use a standard file extension (.json, .xml, .yaml, .toml, .csv)

**Cache Issues**
- Use `--clear-cache` to reset cache file
- Check write permissions in current directory
- Adjust `--cache-age` for different cache behavior

### Debugging

Enable verbose output by checking API responses and using cache debugging:

```bash
# Clear cache and run with fresh data
dotseek -clear-cache
dotseek -no-cache -a -d myapp
```
