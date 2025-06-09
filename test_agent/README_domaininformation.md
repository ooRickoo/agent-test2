# Domain Information Tool

A comprehensive domain investigation tool that gathers WHOIS, DNS, and VirusTotal information about any domain or FQDN.

## Features

- WHOIS data retrieval
- Comprehensive DNS information:
  - Standard records (A, AAAA, CNAME, MX, TXT)
  - Advanced records (SRV, CAA, NS, SOA, DNSKEY)
  - DNS record summary with referenced records highlighted
- Name server authority status checking
- Domain age analysis with warnings for newly registered domains
- VirusTotal reputation data integration
- Full FQDN and subdomain support:
  - Automatically extracts the base domain
  - Shows record types (A, AAAA, CNAME) for subdomains and non-domain inputs
  - Shows domain-level MX and TXT records for any input
- Multiple output formats (text, JSON, CSV)
- Batch processing for analyzing multiple domains at once
- Caching system to reduce API calls and improve performance
- Enhanced output for malicious domains

## Requirements

- Python 3.6+
- Required packages:
  - python-whois
  - dnspython
  - vt-py (for VirusTotal integration)

## Installation

1. Install required packages:

```bash
pip install python-whois dnspython vt-py
```

2. Clone or download this repository

3. Make the script executable:

```bash
chmod +x domaininformation.py
```

## Usage

### Basic Usage

```bash
# Basic domain lookup
python domaininformation.py example.com

# Subdomain lookup (shows A/AAAA/CNAME records and domain info)
python domaininformation.py www.example.com

# Skip VirusTotal lookup
python domaininformation.py example.com --no-vt

# Output in JSON format
python domaininformation.py example.com --output json

# Output in CSV format
python domaininformation.py example.com --output csv

# Batch processing from a file containing domains
python domaininformation.py domains.txt --batch

# Batch processing with 10 parallel threads
python domaininformation.py domains.txt --batch --threads 10
```

### Using VirusTotal API

To use the VirusTotal integration, you need to:

1. [Sign up for a VirusTotal account](https://www.virustotal.com/gui/join-us)
2. Get your API key from your account settings
3. Provide your API key in one of two ways:

   **Option 1:** Set the API key as an environment variable:
   ```bash
   # For Linux/Mac
   export VT_API_KEY="your_api_key_here"

   # For Windows
   set VT_API_KEY=your_api_key_here
   ```

   **Option 2:** Create a `.vt_api_key` file in the same directory as the script:
   ```bash
   echo "your_api_key_here" > .vt_api_key
   ```

### Examples

#### Analyzing a Domain
```bash
python domaininformation.py example.com
```

#### Analyzing a Subdomain
```bash
python domaininformation.py www.example.com
```
This will:
1. Show record types (A/AAAA/CNAME) for www.example.com
2. Show the base domain (example.com) information
3. Show MX and TXT records for both the subdomain and base domain

#### Checking a Non-Existent Subdomain
```bash
python domaininformation.py api.example.com
```
This will indicate that no records exist for the subdomain but will still show the base domain information.

## Output

The tool provides information in several sections:

1. **WHOIS Information**: Registration details, dates, registrar
2. **DNS Information**: 
   - DNS Records Summary (A, AAAA, CNAME with referenced IPs highlighted)
   - Nameservers (with authority status)
   - MX records
   - TXT records
   - SRV records
   - CAA records
   - SOA record
   - DNSKEY records
3. **VirusTotal Analysis**: Security vendor ratings, categories, community votes
4. **Domain Status**: Summary and warnings (if applicable)

### DNS Records Summary

The DNS Records Summary shows a comprehensive view of DNS records for the domain, including A, AAAA, CNAME, MX, and NS records. Records that are referenced by other DNS records (like MX, NS, or CNAME records) are marked with an asterisk (*) and sorted to the top of the table:

```
=== DNS Records Summary ===
A Records:
* 93.184.216.34
  93.184.216.43

AAAA Records:
* 2606:2800:220:1:248:1893:25c8:1946

CNAME Records:
  cdn.example.com

MX Records:
  10 mail.example.com

NS Records:
  ns1.example.com
  ns2.example.com

* Records marked with asterisk are referenced by CNAME, MX, or NS records
```

## Output Formats

### Text Output (Default)
The default output is formatted text displayed in the terminal, organized by sections.

### JSON Output
When using `--output json`, the tool outputs a structured JSON object containing all the gathered information:

```json
{
  "domain": "example.com",
  "whois": {
    "domain": "example.com",
    "registrar": "Example Registrar, LLC",
    "creation_date": "1995-08-14 04:00:00",
    "expiration_date": "2022-08-13 04:00:00"
    // more WHOIS data...
  },
  "dns": {
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "mx_records": ["10 mail.example.com"],
    "txt_records": ["v=spf1 include:_spf.example.com ~all"],
    "dns_records_with_references": {
      "A": [
        {"value": "93.184.216.34", "referenced": true},
        {"value": "93.184.216.43", "referenced": false}
      ],
      "AAAA": [
        {"value": "2606:2800:220:1:248:1893:25c8:1946", "referenced": true}
      ],
      "CNAME": [
        {"value": "cdn.example.com", "referenced": false}
      ]
    },
    // more DNS data...
  },
  "virustotal": {
    "available": true,
    "malicious": 0,
    "suspicious": 0,
    "harmless": 67
    // more VirusTotal data...
  },
  "newly_registered": false
}
```

### CSV Output
When using `--output csv`, the tool creates a CSV file named `<domain>_whois_dns_info.csv` that contains all the gathered information.

## Batch Processing

To analyze multiple domains, create a text file with one domain per line:

```
example.com
example.org
example.net
www.example.com
```

Then run:

```bash
python domaininformation.py domains.txt --batch
```

For faster processing, you can use multiple threads:

```bash
python domaininformation.py domains.txt --batch --threads 10
```

## Caching

The tool implements a caching system for DNS lookups and VirusTotal API calls:

- DNS queries are cached for 1 hour to reduce repeated lookups
- VirusTotal API calls are cached to stay within API rate limits and improve response time
- WHOIS information is cached to reduce load on WHOIS servers

## Note

- Recently registered domains (less than 6 months old) are highlighted as potential security risks
- Domains flagged by multiple security vendors on VirusTotal are marked with detailed warnings
- The more security vendors flag a domain as malicious, the more detailed the warning information
