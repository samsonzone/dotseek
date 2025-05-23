# DotSeek

**DotSeek** is a powerful command-line tool for checking domain availability using the Namecheap API. It provides intelligent caching, TLD filtering, and batch processing capabilities to help you find the perfect domain name efficiently.

## Features

- **Fast Domain Checking**: Batch API calls with intelligent caching
- **TLD Filtering**: Filter by length, keywords, or custom criteria  
- **Premium Detection**: Identify premium domains with pricing indicators
- **Smart Caching**: Configurable cache with automatic expiration
- **Colored Output**: Easy-to-read results with color-coded availability
- **Multiple TLD Sources**: Remote URL, local file, or embedded TLD lists
- **Sandbox Support**: Test with Namecheap's sandbox environment
- **TLD Descriptions**: Optional keyword descriptions for TLD context

## Installation

### Prerequisites

- Go 1.19 or higher
- Namecheap API account with API access enabled

### Build from Source

```bash
git clone <repository-url>
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
dotseek myapp -l 3          # Only 3-character TLDs (.com, .net, .org)
dotseek myapp -l "<4"       # TLDs shorter than 4 characters  
dotseek myapp -l ">=5"      # TLDs 5 characters or longer
```

Filter by keywords:
```bash
dotseek myapp -k "tech,business"     # Include tech/business TLDs
dotseek myapp -ek "adult,gambling"   # Exclude adult/gambling TLDs
```

### Display Options

Show all domains (available and unavailable):
```bash
dotseek myapp -a
```

Include premium domains in results:
```bash
dotseek myapp -p
```

Show TLD descriptions:
```bash
dotseek myapp -d
# or
dotseek myapp -tld-descriptions
```

### Cache Management

Disable cache for current run:
```bash
dotseek myapp -no-cache
```

Clear cache file:
```bash
dotseek -clear-cache
```

Set custom cache age (in seconds):
```bash
dotseek myapp -cache-age 3600  # 1 hour
```

### Custom TLD File

Use a custom TLD file instead of the default sources:
```bash
dotseek myapp -tld-file custom_tlds.csv
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

1. **Remote URL**: `https://raw.githubusercontent.com/samsonzone/freedot-cli/refs/heads/main/ref/tlds.txt`
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
dotseek mystartup -l "<=4" -k "tech,startup" -p -d
```

### E-commerce Domain Search  
```bash
# Find business-appropriate domains, excluding adult content
dotseek mystore -k "business,commercial" -ek "adult,gambling" -a
```

### Developer Portfolio
```bash
# Find developer-focused domains with descriptions
dotseek johndoe -k "tech,development,personal" -d
```

### Comprehensive Domain Research
```bash
# Check everything, show all results with detailed info
dotseek brandname -a -p -d -cache-age 7200
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

**Cache Issues**
- Use `--clear-cache` to reset cache file
- Check write permissions in current directory
- Adjust `--cache-age` for different cache behavior

### Debugging

Enable verbose output by checking API responses and using cache debugging:

```bash
# Clear cache and run with fresh data
dotseek -clear-cache
dotseek myapp -no-cache -a -d
```