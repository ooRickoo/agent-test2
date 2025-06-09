#!/usr/bin/env python3
"""
Domain Information Tool

This tool provides comprehensive information about a domain or subdomain including:
- WHOIS data for the base domain
- DNS information (MX, TXT records) 
- Name server authority status
- Domain age analysis with warnings for recently registered domains
- Record type information for subdomains (A, AAAA, CNAME)
- VirusTotal reputation data

Usage: 
    python domaininformation.py example.com
    python domaininformation.py www.example.com
    python domaininformation.py example.com --no-vt
    python domaininformation.py example.com --output json
    python domaininformation.py domains.txt --batch

Author: Rick
Date: May 23, 2025
"""
import whois as whoislookup
import datetime
import sys
import socket
from whois.parser import PywhoisError
import re
import argparse
import asyncio
import os
import json
import urllib.request
import urllib.error
import dns.resolver
import dns.flags
import dns.message
import dns.query
import csv
from pathlib import Path
import time
import functools
from concurrent.futures import ThreadPoolExecutor

# Check for DNS availability
DNS_AVAILABLE = True

# We'll use a direct REST API call instead of the vt-py library
# to avoid async/await complications
VT_AVAILABLE = True

# ANSI colors for terminal output (only used for high-risk domains)
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Cache for DNS and VirusTotal results
DNS_CACHE = {}
VT_CACHE = {}
WHOIS_CACHE = {}
CACHE_EXPIRY = 3600  # Cache results for 1 hour (in seconds)

def cache_result(cache_dict, key, result):
    """Cache a result with timestamp."""
    cache_dict[key] = {
        'timestamp': time.time(),
        'data': result
    }
    return result

def get_cached_result(cache_dict, key):
    """Get a result from cache if it exists and is not expired."""
    if key in cache_dict:
        entry = cache_dict[key]
        if time.time() - entry['timestamp'] < CACHE_EXPIRY:
            return entry['data']
    return None

def extract_domain(fqdn):
    """Extract the base domain from an FQDN.
    
    Returns a tuple of (domain, hostname_type) where:
    domain - The registrable domain
    hostname_type - Whether the input is 'domain', 'subdomain', 'ip' or 'unknown'
    """
    # Check if the input is an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, fqdn):
        return fqdn, "ip"
        
    # This regex matches domain patterns
    domain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    match = re.search(domain_pattern, fqdn)
    if not match:
        return fqdn, "unknown"  # Return the input if no match found
    
    full_domain = match.group(0)
    parts = full_domain.split('.')
    
    # Determine if this is a subdomain or just a domain
    hostname_type = "domain"
    if len(parts) > 2:
        hostname_type = "subdomain"
        
    # If we have more than 2 parts, try to determine the registrable domain
    if len(parts) > 2:
        # Handle common multi-part TLDs
        common_suffixes = ['co.uk', 'com.au', 'org.uk', 'net.au', 'gov.uk', 'edu.au', 
                          'ac.uk', 'gov.au', 'co.nz', 'org.nz', 'net.nz']
        last_two = '.'.join(parts[-2:])
        if last_two in common_suffixes and len(parts) > 2:
            return '.'.join(parts[-3:]), hostname_type
        
        # Common case: something.example.com -> example.com
        return '.'.join(parts[-2:]), hostname_type
    
    return full_domain, hostname_type

def is_newly_registered(date_str):
    """Determine if a domain is newly registered (less than 6 months old)."""
    try:
        if date_str == "Not available":
            return False
            
        # Handle multiple creation dates (take the earliest one)
        if ";" in date_str:
            earliest_date = None
            for date_part in date_str.split(";"):
                date_part = date_part.strip()
                if not date_part:
                    continue
                parsed_date = datetime.datetime.strptime(date_part, '%Y-%m-%d %H:%M:%S')
                if earliest_date is None or parsed_date < earliest_date:
                    earliest_date = parsed_date
            if earliest_date is None:
                return False
            date_to_check = earliest_date
        else:
            date_to_check = datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
            
        # Calculate time difference
        current_date = datetime.datetime.now()
        age_months = (current_date.year - date_to_check.year) * 12 + (current_date.month - date_to_check.month)
        return age_months < 6
    except Exception:
        return False

def get_mx_records(domain):
    """Get MX records for a domain."""
    if not DNS_AVAILABLE:
        return ["DNS functionality not available (dnspython not installed)"]
    
    # Check cache first
    cached_result = get_cached_result(DNS_CACHE, f"mx_{domain}")
    if cached_result is not None:
        return cached_result
    
    try:
        mx_records = []
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            # Extract preference and exchange
            mx_records.append(f"{rdata.preference} {rdata.exchange}")
        
        # Cache the result
        cache_result(DNS_CACHE, f"mx_{domain}", mx_records)
        return mx_records
    except Exception as e:
        return [f"Error retrieving MX records: {e}"]

def get_txt_records(domain):
    """Get TXT records for a domain."""
    if not DNS_AVAILABLE:
        return ["DNS functionality not available (dnspython not installed)"]
    
    # Check cache first
    cached_result = get_cached_result(DNS_CACHE, f"txt_{domain}")
    if cached_result is not None:
        return cached_result
    
    try:
        txt_records = []
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            # Join TXT strings and decode
            txt = b''.join(rdata.strings).decode('utf-8')
            txt_records.append(txt)
        
        # Cache the result
        cache_result(DNS_CACHE, f"txt_{domain}", txt_records)
        return txt_records
    except Exception as e:
        return [f"Error retrieving TXT records: {e}"]

def get_a_record(hostname):
    """Get A records (IPv4) for a hostname."""
    if not DNS_AVAILABLE:
        return []
    
    # Check cache first
    cached_result = get_cached_result(DNS_CACHE, f"a_{hostname}")
    if cached_result is not None:
        return cached_result
    
    try:
        a_records = []
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            # Use @ for the root domain only, otherwise use the leftmost label for subdomains
            domain = answers.qname.to_text().rstrip('.')
            if hostname == domain:
                record_name = "@"
            else:
                # For subdomains, show only the leftmost label (e.g., 'www' for 'www.example.com')
                parts = hostname.split('.')
                if len(parts) > 2:
                    record_name = parts[0]
                else:
                    record_name = hostname
            a_records.append(f"{record_name}:{str(rdata)}")
        
        # Cache the result
        cache_result(DNS_CACHE, f"a_{hostname}", a_records)
        return a_records
    except Exception:
        return []

def get_aaaa_record(hostname):
    """Get AAAA records (IPv6) for a hostname."""
    if not DNS_AVAILABLE:
        return []
    
    # Check cache first
    cached_result = get_cached_result(DNS_CACHE, f"aaaa_{hostname}")
    if cached_result is not None:
        return cached_result
    
    try:
        aaaa_records = []
        answers = dns.resolver.resolve(hostname, 'AAAA')
        for rdata in answers:
            record_name = hostname
            # Use @ for the root domain
            if hostname == answers.qname.to_text().rstrip('.'):
                record_name = "@"
            # Strip the domain part if it's a subdomain
            elif '.' in hostname:
                parts = hostname.split('.')
                if len(parts) > 2:
                    record_name = parts[0]
            aaaa_records.append(f"{record_name}:{str(rdata)}")
        
        # Cache the result
        cache_result(DNS_CACHE, f"aaaa_{hostname}", aaaa_records)
        return aaaa_records
    except Exception:
        return []

def get_cname_record(hostname):
    """Get CNAME record for a hostname."""
    if not DNS_AVAILABLE:
        return []
    
    # Check cache first
    cached_result = get_cached_result(DNS_CACHE, f"cname_{hostname}")
    if cached_result is not None:
        return cached_result
    
    try:
        cname_records = []
        answers = dns.resolver.resolve(hostname, 'CNAME')
        for rdata in answers:
            record_name = hostname
            # Strip the domain part if it's a subdomain
            if '.' in hostname:
                parts = hostname.split('.')
                if len(parts) > 2:
                    record_name = hostname  # Show the full alias name for clarity
            cname_records.append(f"{record_name} → {str(rdata.target)}")
        
        # Cache the result
        cache_result(DNS_CACHE, f"cname_{hostname}", cname_records)
        return cname_records
    except Exception:
        return []

def check_record_type(hostname):
    """Check if hostname has A, AAAA, or CNAME records."""
    results = {}
    
    a_records = get_a_record(hostname)
    if a_records:
        results['A'] = a_records
    
    aaaa_records = get_aaaa_record(hostname)
    if aaaa_records:
        results['AAAA'] = aaaa_records
    
    cname_records = get_cname_record(hostname)
    if cname_records:
        results['CNAME'] = cname_records
    
    return results

def check_dns_server_type(domain, nameserver):
    """Check if a DNS server is Authoritative, Forwarding, or Cache-only."""
    if not DNS_AVAILABLE:
        return "DNS check not available"
    
    try:
        # Create a resolver that uses this specific nameserver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(nameserver)]
        resolver.timeout = 2
        resolver.lifetime = 4
        
        # Query the nameserver for SOA record with recursion disabled
        query = dns.message.make_query(domain, dns.rdatatype.SOA)
        query.flags &= ~dns.flags.RD  # Turn off Recursion Desired flag
        
        try:
            response = dns.query.udp(query, socket.gethostbyname(nameserver), timeout=2)
            
            # Check if Authoritative Answer flag is set
            if response.flags & dns.flags.AA:
                return "Authoritative"
            else:
                # If not authoritative but has answers, it's forwarding
                if len(response.answer) > 0:
                    return "Forwarding"
                else:
                    # Try a recursive query to check if it's a cache server
                    query.flags |= dns.flags.RD  # Turn on Recursion Desired
                    response = dns.query.udp(query, socket.gethostbyname(nameserver), timeout=2)
                    if len(response.answer) > 0:
                        return "Cache-only"
                    else:
                        return "Unknown"
        except Exception:
            # If non-recursive query fails, try recursive query
            try:
                query = dns.message.make_query(domain, dns.rdatatype.SOA)
                response = dns.query.udp(query, socket.gethostbyname(nameserver), timeout=2)
                if len(response.answer) > 0:
                    return "Cache-only"
                else:
                    return "Unknown"
            except Exception:
                return "Unreachable"
    except Exception as e:
        return f"Error: {str(e)}"

def get_virustotal_info(domain):
    """Get domain reputation information from VirusTotal using direct REST API."""
    if not VT_AVAILABLE:
        return {
            "available": False,
            "message": "VirusTotal functionality not available"
        }
    
    # Check for API key
    api_key = os.environ.get('VT_API_KEY')
    if not api_key:
        # Try to read from a config file as fallback
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.vt_api_key')
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    api_key = f.read().strip()
        except:
            pass
            
    if not api_key:
        return {
            "available": False,
            "message": "VirusTotal API key not found. Set it as environment variable VT_API_KEY or create a .vt_api_key file"
        }
    
    # Check cache first
    cached_result = get_cached_result(VT_CACHE, domain)
    if cached_result is not None:
        return cached_result
    
    try:
        # Prepare the request
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        
        # Create the request
        req = urllib.request.Request(url, headers=headers)
        
        # Create SSL context that doesn't verify
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Execute the request with SSL context
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            # Parse the JSON response
            data = json.loads(response.read().decode('utf-8'))
            
            # Extract the attributes
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get analysis stats
            stats = attributes.get('last_analysis_stats', {})
            
            # Get reputation score
            reputation = attributes.get('reputation')
            
            # Get categories
            categories = attributes.get('categories', {})
            
            # Get creation date if available
            creation_date_raw = attributes.get('creation_date')
            creation_date = None
            if creation_date_raw:
                creation_date = datetime.datetime.fromtimestamp(creation_date_raw).strftime('%Y-%m-%d %H:%M:%S')
                
            # Get votes info
            total_votes = attributes.get('total_votes', {})
            harmless_votes = total_votes.get('harmless', 0)
            malicious_votes = total_votes.get('malicious', 0)
        
        # Cache the result
        vt_result = {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": reputation,
            "categories": categories,
            "creation_date": creation_date,
            "registrar": "Not available",  # VT API doesn't reliably provide this
            "total_votes": {
                "harmless": harmless_votes,
                "malicious": malicious_votes
            }
        }
        cache_result(VT_CACHE, domain, vt_result)
        return vt_result
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "available": False,
                "message": f"Domain '{domain}' not found in VirusTotal database"
            }
        elif e.code == 401:
            return {
                "available": False,
                "message": f"VirusTotal API authentication failed. Check your API key."
            }
        elif e.code == 429:
            return {
                "available": False,
                "message": f"VirusTotal API quota exceeded. Try again later or upgrade your API key."
            }
        else:
            return {
                "available": False,
                "message": f"VirusTotal API error: HTTP {e.code} - {e.reason}"
            }
    except Exception as e:
        return {
            "available": False,
            "message": f"Error retrieving VirusTotal information: {e}"
        }

def format_vt_results(vt_info, is_new_domain):
    """Format VirusTotal results for display."""
    if not vt_info["available"]:
        return f"VirusTotal information: {vt_info['message']}"
    
    output = []
    output.append("\n=== VirusTotal Analysis ===")
    
    # Calculate risk level
    malicious = vt_info["malicious"]
    suspicious = vt_info["suspicious"]
    harmless = vt_info["harmless"]
    reputation = vt_info["reputation"]
    
    # Determine risk level
    risk_level = "Unknown"
    if malicious > 0:
        if malicious >= 5:
            risk_level = f"{RED}{BOLD}HIGH RISK{RESET}"
        else:
            risk_level = f"{YELLOW}Medium Risk{RESET}"
    elif suspicious > 0:
        risk_level = f"{YELLOW}Suspicious{RESET}"
    elif harmless > 10:
        risk_level = f"{GREEN}Low Risk{RESET}"
    
    # Format the summary based on risk
    output.append(f"Risk Assessment: {risk_level}")
    output.append(f"Security Vendors:")
    output.append(f"  Flagged as malicious: {malicious}")
    output.append(f"  Flagged as suspicious: {suspicious}")
    output.append(f"  Flagged as harmless: {harmless}")
    output.append(f"  Undetected: {vt_info['undetected']}")
    
    # Show reputation score
    if reputation is not None:
        output.append(f"Reputation Score: {reputation} (-100 to +100, higher is better)")
    
    # Show categories if available
    if vt_info["categories"]:
        output.append("Categories:")
        for vendor, category in vt_info["categories"].items():
            output.append(f"  {vendor}: {category}")
    
    # Show community votes
    votes = vt_info["total_votes"]
    output.append(f"Community Votes: {votes['harmless']} harmless, {votes['malicious']} malicious")
    
    # If the domain is high risk or newly registered, show more detailed warnings
    if malicious >= 5 or (is_new_domain and (malicious > 0 or suspicious > 0)):
        output.append(f"\n{RED}{BOLD}WARNING: This domain has been flagged as potentially malicious by multiple security vendors!{RESET}")
        output.append(f"{RED}Exercise extreme caution with this domain. Do not download files or enter credentials.{RESET}")
        if is_new_domain:
            output.append(f"{RED}This is a newly registered domain, which increases the risk profile.{RESET}")
    
    return "\n".join(output)

def output_results(domain, whois_info, dns_info, vt_info, is_new_domain, output_format="text", extended_dns=False):
    """Output the results to console or file in specified format (text, json, csv)."""
    if output_format == "json":
        # Prepare JSON output
        # Convert the sorted records to a JSON-friendly format
        json_friendly_sorted_records = {}
        if 'sorted_records' in dns_info:
            for record_type, records in dns_info['sorted_records'].items():
                json_friendly_sorted_records[record_type] = [
                    {"value": value, "referenced": is_referenced} 
                    for value, is_referenced in records
                ]
        
        # Create a copy of dns_info without the full sorted_records and dns_summary
        dns_info_json = {k: v for k, v in dns_info.items() 
                         if k not in ('sorted_records', 'dns_summary')}
        
        # Add the JSON-friendly sorted records
        dns_info_json['dns_records_with_references'] = json_friendly_sorted_records
        
        output_data = {
            "domain": domain,
            "whois": whois_info,
            "dns": dns_info_json,
            "virustotal": vt_info,
            "newly_registered": is_new_domain
        }
        
        # Print JSON to console
        print(json.dumps(output_data, indent=4))
        
    elif output_format == "csv":
        # Prepare CSV output
        csv_file = f"{domain}_whois_dns_info.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            
            # Write header
            writer.writerow(["Category", "Detail"])
            
            # Write WHOIS information
            writer.writerow(["WHOIS Information", ""])
            for key, value in whois_info.items():
                writer.writerow([key, value])
            
            # Write DNS information
            writer.writerow(["DNS Information", ""])
            for key, value in dns_info.items():
                if isinstance(value, list):
                    writer.writerow([key, ", ".join(str(item) for item in value)])
                elif isinstance(value, dict):
                    writer.writerow([key, json.dumps(value)])
                else:
                    writer.writerow([key, value])
            
            # Write VirusTotal information
            writer.writerow(["VirusTotal Information", ""])
            for key, value in vt_info.items():
                if isinstance(value, dict):
                    writer.writerow([key, json.dumps(value)])
                else:
                    writer.writerow([key, value])
        
        print(f"Results saved to {csv_file}")
    
    else:
        # Default to text output
        print("=== WHOIS Information ===")
        print(f"Domain name: {whois_info['domain']}")
        print(f"Registrar: {whois_info['registrar']}")
        print(f"Whois server: {whois_info['whois_server']}")
        if is_new_domain:
            print(f"Creation date: {whois_info['creation_date']} [RECENT REGISTRATION]")
        else:
            print(f"Creation date: {whois_info['creation_date']}")
        print(f"Expiration date: {whois_info['expiration_date']}")
        print(f"Update date: {whois_info['updated_date']}")
        print(f"DNSSEC: {whois_info['dnssec']}")
        print("\n=== DNS Information ===")
        if extended_dns:
            # Print DNS Records Summary if available
            if dns_info.get('dns_summary'):
                print(dns_info['dns_summary'])
            # Show TXT records only in extended DNS mode
            print(f"\nTXT Records for {domain}:")
            if dns_info['txt_records']:
                for record in dns_info['txt_records']:
                    print(f"  {record}")
            else:
                print("  None found")
        else:
            # Only show NS records and their authority/forwarding status
            print(f"\nName servers for {domain}:")
            if dns_info['name_servers']:
                for ns in dns_info['name_servers']:
                    server_type = check_dns_server_type(domain, ns)
                    print(f"  {ns} - {server_type}")
            else:
                print("  None listed")
        
        # Display MX records
        print(f"\nMX Records for {domain}:")
        if dns_info['mx_records']:
            for record in dns_info['mx_records']:
                print(f"  {record}")
        else:
            print("  None found")

        # Display TXT records
        print(f"\nTXT Records for {domain}:")
        if dns_info['txt_records']:
            for record in dns_info['txt_records']:
                print(f"  {record}")
        else:
            print("  None found")
        
        # Display additional DNS records
        if extended_dns:
            # SRV Records
            if dns_info.get('srv_records'):
                print(f"\nSRV Records for {domain}:")
                if dns_info['srv_records']:
                    for record in dns_info['srv_records']:
                        print(f"  {record}")
                else:
                    print("  None found")
                    
            # CAA Records
            if dns_info.get('caa_records'):
                print(f"\nCAA Records for {domain}:")
                if dns_info['caa_records']:
                    for record in dns_info['caa_records']:
                        print(f"  {record}")
                else:
                    print("  None found")
                
            # SOA Record
            if dns_info.get('soa_record'):
                print(f"\nSOA Record for {domain}:")
                if dns_info['soa_record']:
                    soa = dns_info['soa_record']
                    print(f"  Primary nameserver: {soa['mname']}")
                    print(f"  Admin email: {soa['rname']}")
                    print(f"  Serial: {soa['serial']}")
                    print(f"  Refresh: {soa['refresh']} seconds")
                    print(f"  Retry: {soa['retry']} seconds")
                    print(f"  Expire: {soa['expire']} seconds")
                    print(f"  Minimum TTL: {soa['minimum']} seconds")
                else:
                    print("  None found")
                
            # DNSKEY Records
            if dns_info.get('dnskey_records'):
                print(f"\nDNSKEY Records for {domain}:")
                if dns_info['dnskey_records']:
                    for record in dns_info['dnskey_records']:
                        print(f"  {record}")
                else:
                    print("  None found")
        
        # If this is a subdomain, also show its TXT records if available
        if dns_info.get('subdomain_txt_records'):
            hostname = "subdomain" # This is just a placeholder as we don't have the fqdn here
            print(f"\nTXT Records for {hostname}:")
            if not any(record.startswith("Error") for record in dns_info['subdomain_txt_records']):
                for record in dns_info['subdomain_txt_records']:
                    print(f"  {record}")
            else:
                print("  None found")

        # Display VirusTotal results
        print(format_vt_results(vt_info, is_new_domain))

        # Display conclusion about domain status
        print("\n=== Domain Status ===")
        status = whois_info.get('status')
        if status:
            if isinstance(status, list) and status:
                print("Domain appears to be registered and active.")
            elif status:
                print("Domain appears to be registered and active.")
            else:
                print("Domain is registered but may not be active.")
        else:
            print("Limited information available about this domain.")

        # Display warning for new domains
        if is_new_domain:
            print(f"\n⚠️  WARNING: This domain was registered within the last 6 months!")
            print("Recently registered domains are frequently used for malicious purposes.")
            print("Exercise caution when interacting with this domain or its services.")

def analyze_domain(fqdn, no_vt=False, output_format="text", extended_dns=False):
    """Analyze a single domain or FQDN and return the results."""
    # Extract the domain part if it's an FQDN with subdomains
    domain, hostname_type = extract_domain(fqdn)
    
    print(f"\nAnalyzing: {fqdn}")
    
    # Handle IP address inputs differently
    if hostname_type == "ip":
        print("This appears to be an IP address rather than a domain.")
        print("Please use an appropriate IP lookup tool instead.")
        print(f"Tip: Try using the hostinformation.py or ip_geolocation.py script for IP {fqdn}")
        return 0
    
    # Check record types if this is a subdomain or hostname
    original_hostname_records = {}
    if hostname_type == "subdomain":
        print(f"Base domain: {domain}")
        original_hostname_records = check_record_type(fqdn)
        
        if original_hostname_records:
            print("\n=== Record Type Information ===")
            for record_type, values in original_hostname_records.items():
                record_label = "record" if len(values) == 1 else "records"
                print(f"{record_type} {record_label} for {fqdn}:")
                for value in values:
                    print(f"  {value}")
        else:
            print("\n=== Record Type Information ===")
            print(f"No A, AAAA, or CNAME records found for {fqdn}")
    elif hostname_type == "unknown":
        print("Warning: This doesn't appear to be a valid domain name.")
    
    print("")
    
    try:
        # Get WHOIS information
        r = whoislookup.whois(domain)
    except PywhoisError as e:
        error_msg = str(e)
        if "No match for" in error_msg or "NOT FOUND" in error_msg.upper() or "No Data Found" in error_msg:
            print(f"Domain not found: {domain} is not registered or not available for lookup")
        else:
            print(f"WHOIS Error: {e}")
        return 1
    except Exception as e:
        print(f"Connection Error: {e}")
        return 2

    # Process creation date
    create_date = "Not available"
    is_new_domain = False
    
    if hasattr(r, 'creation_date') and r.creation_date:
        if isinstance(r.creation_date, list):
            create_date = []
            for date in r.creation_date:
                if date:
                    create_date.append(date.strftime('%Y-%m-%d %H:%M:%S'))
            create_date = "; ".join(create_date) if create_date else "Not available"
        elif r.creation_date:
            create_date = r.creation_date.strftime('%Y-%m-%d %H:%M:%S')
    
    # Check if the domain is newly registered
    is_new_domain = is_newly_registered(create_date)
    
    # Process updated date
    update_date = "Not available"
    if hasattr(r, 'updated_date') and r.updated_date:
        if isinstance(r.updated_date, list):
            update_date = []
            for date in r.updated_date:
                if date:
                    update_date.append(date.strftime('%Y-%m-%d %H:%M:%S'))
            update_date = "; ".join(update_date) if update_date else "Not available"
        elif r.updated_date:
            update_date = r.updated_date.strftime('%Y-%m-%d %H:%M:%S')

    # Process expiration date
    expiration_date = "Not available"
    if hasattr(r, 'expiration_date') and r.expiration_date:
        if isinstance(r.expiration_date, list):
            expiration_date = []
            for date in r.expiration_date:
                if date:
                    expiration_date.append(date.strftime('%Y-%m-%d %H:%M:%S'))
            expiration_date = "; ".join(expiration_date) if expiration_date else "Not available"
        elif r.expiration_date:
            expiration_date = r.expiration_date.strftime('%Y-%m-%d %H:%M:%S')

    # Get DNS records - always use the base domain for MX and TXT
    mx_records = get_mx_records(domain)  # MX records are typically at the domain level
    txt_records = get_txt_records(domain)  # TXT records are typically at the domain level
    
    # Get additional DNS records for enhanced information
    srv_records = get_srv_records(domain)
    caa_records = get_caa_records(domain)
    ns_records = get_ns_records(domain)
    soa_record = get_soa_record(domain)
    dnskey_records = get_dnskey_records(domain)
    
    # Get DNS records with references
    references = get_referenced_records(domain)
    sorted_records = sort_dns_records(references, references['referenced_ips'])
    dns_summary = format_dns_summary(sorted_records)
    
    # For subdomains, also check their specific records
    subdomain_txt_records = []
    if hostname_type == "subdomain" and fqdn != domain:
        subdomain_txt_records = get_txt_records(fqdn)

    # Get VirusTotal information (now synchronously) for the base domain if not skipped
    vt_info = {"available": False, "message": "VirusTotal lookup skipped"} if no_vt else get_virustotal_info(domain)

    # Prepare output data
    whois_info = {
        "domain": domain,
        "registrar": getattr(r, 'registrar', "Not available"),
        "whois_server": getattr(r, 'whois_server', "Not available"),
        "creation_date": create_date,
        "expiration_date": expiration_date,
        "updated_date": update_date,
        "dnssec": getattr(r, 'dnssec', "Not available"),
        "status": getattr(r, 'status', "Not available")
    }
    
    dns_info = {
        "name_servers": getattr(r, 'name_servers', []),
        "mx_records": mx_records,
        "txt_records": txt_records,
        "subdomain_txt_records": subdomain_txt_records,
        "srv_records": srv_records,
        "caa_records": caa_records,
        "ns_records": ns_records,
        "soa_record": soa_record,
        "dnskey_records": dnskey_records,
        "dns_summary": dns_summary,
        "sorted_records": sorted_records
    }

    # Output results in the requested format
    output_results(domain, whois_info, dns_info, vt_info, is_new_domain, output_format, extended_dns)

    return 0

def get_srv_records(domain, service='_sip._tcp'):
    """Get SRV records for a domain."""
    if not DNS_AVAILABLE:
        return []
    
    # Check cache first
    cache_key = f"srv_{domain}_{service}"
    cached_result = get_cached_result(DNS_CACHE, cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        srv_records = []
        # If service was not provided in the domain, prepend it
        full_domain = domain
        if not domain.startswith('_'):
            full_domain = f"{service}.{domain}"
            
        answers = dns.resolver.resolve(full_domain, 'SRV')
        for rdata in answers:
            srv_records.append(f"Priority: {rdata.priority}, Weight: {rdata.weight}, "
                               f"Port: {rdata.port}, Target: {rdata.target}")
        
        # Cache the result
        cache_result(DNS_CACHE, cache_key, srv_records)
        return srv_records
    except Exception:
        return []

def get_caa_records(domain):
    """Get CAA (Certification Authority Authorization) records."""
    if not DNS_AVAILABLE:
        return []
    
    # Check cache first
    cache_key = f"caa_{domain}"
    cached_result = get_cached_result(DNS_CACHE, cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        caa_records = []
        answers = dns.resolver.resolve(domain, 'CAA')
        for rdata in answers:
            caa_records.append(f"Flag: {rdata.flags}, Tag: {rdata.tag}, Value: {rdata.value}")
        
        # Cache the result
        cache_result(DNS_CACHE, cache_key, caa_records)
        return caa_records
    except Exception:
        return []

def get_ns_records(domain):
    """Get NS records for a domain."""
    if not DNS_AVAILABLE:
        return []
    
    # Check cache first
    cache_key = f"ns_{domain}"
    cached_result = get_cached_result(DNS_CACHE, cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        ns_records = []
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            ns_records.append(str(rdata.target))
        
        # Cache the result
        cache_result(DNS_CACHE, cache_key, ns_records)
        return ns_records
    except Exception:
        return []

def get_soa_record(domain):
    """Get SOA record for a domain."""
    if not DNS_AVAILABLE:
        return None
    
    # Check cache first
    cache_key = f"soa_{domain}"
    cached_result = get_cached_result(DNS_CACHE, cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        for rdata in answers:
            soa_info = {
                'mname': str(rdata.mname),
                'rname': str(rdata.rname),
                'serial': rdata.serial,
                'refresh': rdata.refresh,
                'retry': rdata.retry,
                'expire': rdata.expire,
                'minimum': rdata.minimum
            }
            # Cache the result
            cache_result(DNS_CACHE, cache_key, soa_info)
            return soa_info
    except Exception:
        return None

def get_dnskey_records(domain):
    """Get DNSKEY records for a domain."""
    if not DNS_AVAILABLE:
        return []
    
    # Check cache first
    cache_key = f"dnskey_{domain}"
    cached_result = get_cached_result(DNS_CACHE, cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        dnskey_records = []
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        for rdata in answers:
            dnskey_records.append(f"Flags: {rdata.flags}, Protocol: {rdata.protocol}, "
                                 f"Algorithm: {rdata.algorithm}")
        
        # Cache the result
        cache_result(DNS_CACHE, cache_key, dnskey_records)
        return dnskey_records
    except Exception:
        return []

def get_referenced_records(domain):
    """
    Collects all DNS records for a domain and identifies which A/AAAA records are
    referenced by other records like CNAME, MX, NS.
    
    Returns a dictionary with all records and a set of referenced IPs.
    """
    # Get all the records
    a_records = get_a_record(domain)
    aaaa_records = get_aaaa_record(domain)
    cname_records = get_cname_record(domain)
    mx_records = get_mx_records(domain)
    ns_records = get_ns_records(domain)
    srv_records = get_srv_records(domain)
    
    # Create a mapping of hostnames to their IP addresses
    hostname_to_ip = {}
    
    # Process A records
    for record in a_records:
        hostname_to_ip.setdefault(domain, set()).add(record)
    
    # Track which IPs are referenced by other records
    referenced_ips = set()
    
    # Check CNAME references
    cname_targets = []
    for cname in cname_records:
        cname_targets.append(cname)
        # Resolve the CNAME target to find its IPs
        try:
            target_ips = get_a_record(cname)
            for ip in target_ips:
                referenced_ips.add(ip)
        except Exception:
            pass
    
    # Check MX references
    for mx in mx_records:
        # Extract the MX target hostname
        parts = mx.split()
        if len(parts) >= 2:
            mx_host = parts[1].rstrip('.')
            try:
                # Look up A records for the MX hostname
                mx_ips = get_a_record(mx_host)
                for ip in mx_ips:
                    referenced_ips.add(ip)
            except Exception:
                pass
    
    # Check NS references
    for ns in ns_records:
        ns_host = ns.rstrip('.')
        try:
            # Look up A records for the NS hostname
            ns_ips = get_a_record(ns_host)
            for ip in ns_ips:
                referenced_ips.add(ip)
        except Exception:
            pass
    
    # Combine all records
    all_records = {
        'A': a_records,
        'AAAA': aaaa_records,
        'CNAME': cname_records,
        'MX': mx_records,
        'NS': ns_records,
        'SRV': srv_records,
    }
    
    return {
        'records': all_records,
        'referenced_ips': referenced_ips
    }

def sort_dns_records(records_dict, referenced_ips):
    """
    Sorts DNS records with referenced IPs at the top.
    Returns sorted lists of A, AAAA, CNAME, MX, and NS records.
    """
    # Sort A records
    sorted_a = []
    # First add the referenced IPs
    for ip in records_dict['records']['A']:
        if ip in referenced_ips:
            sorted_a.append((ip, True))  # True indicates it's referenced
    # Then add the non-referenced IPs
    for ip in records_dict['records']['A']:
        if ip not in referenced_ips:
            sorted_a.append((ip, False))  # False indicates it's not referenced
    
    # Sort AAAA records (same logic as A records)
    sorted_aaaa = []
    for ip in records_dict['records']['AAAA']:
        if ip in referenced_ips:
            sorted_aaaa.append((ip, True))
    for ip in records_dict['records']['AAAA']:
        if ip not in referenced_ips:
            sorted_aaaa.append((ip, False))
    
    # CNAME records (no need to sort based on references)
    cname_records = [(cname, False) for cname in records_dict['records']['CNAME']]
    
    # MX records 
    mx_records = [(mx, False) for mx in records_dict['records']['MX']]
    
    # NS records
    ns_records = [(ns, False) for ns in records_dict['records']['NS']]
    
    return {
        'A': sorted_a,
        'AAAA': sorted_aaaa,
        'CNAME': cname_records,
        'MX': mx_records,
        'NS': ns_records
    }

def format_dns_summary(sorted_records):
    """
    Formats the sorted DNS records into a readable summary.
    Includes A, AAAA, CNAME, MX, and NS records.
    """
    summary = []
    summary.append("\n=== DNS Records Summary ===")
    
    # A Records
    if sorted_records['A']:
        summary.append("A Records:")
        for ip, is_referenced in sorted_records['A']:
            prefix = "* " if is_referenced else "  "  # Add star to referenced records
            # Split name and ip from the format "name:ip"
            if ":" in ip:
                name, ip_addr = ip.split(":", 1)
                summary.append(f"{prefix}{name:<15} {ip_addr}")
            else:
                summary.append(f"{prefix}{ip}")
    else:
        summary.append("No A Records found")
    
    # AAAA Records
    if sorted_records['AAAA']:
        summary.append("\nAAAA Records:")
        for ip, is_referenced in sorted_records['AAAA']:
            prefix = "* " if is_referenced else "  "
            # Split name and ip from the format "name:ip"
            if ":" in ip:
                name, ip_addr = ip.split(":", 1)
                summary.append(f"{prefix}{name:<15} {ip_addr}")
            else:
                summary.append(f"{prefix}{ip}")
    else:
        summary.append("\nNo AAAA Records found")
    
    # CNAME Records
    if sorted_records['CNAME']:
        summary.append("\nCNAME Records:")
        for cname, _ in sorted_records['CNAME']:
            summary.append(f"  {cname}")
    else:
        summary.append("\nNo CNAME Records found")
    
    # MX Records
    if sorted_records['MX']:
        summary.append("\nMX Records:")
        for mx, _ in sorted_records['MX']:
            summary.append(f"  {mx}")
    else:
        summary.append("\nNo MX Records found")
    
    # NS Records
    if sorted_records['NS']:
        summary.append("\nNS Records:")
        for ns, _ in sorted_records['NS']:
            summary.append(f"  {ns}")
    else:
        summary.append("\nNo NS Records found")
    
    summary.append("\n* Records marked with asterisk are referenced by CNAME, MX, or NS records")
    
    return "\n".join(summary)

if __name__ == "__main__":
    """Main function to process command-line arguments and execute domain analysis."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Domain Information Tool')
    parser.add_argument('input', help='Domain name, FQDN, or file with list of domains (for batch mode)')
    parser.add_argument('--no-vt', action='store_true', help='Skip VirusTotal lookup')
    parser.add_argument('--output', choices=['text', 'json', 'csv'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--batch', action='store_true', help='Batch process multiple domains from a file')
    parser.add_argument('--threads', type=int, default=4, help='Number of concurrent threads for batch processing (default: 4)')
    parser.add_argument('--extended-dns', action='store_true', help='Show full/extended DNS record summary (A, AAAA, CNAME, MX, etc)')
    args = parser.parse_args()
    
    def output_results(domain, whois_info, dns_info, vt_info, is_new_domain, output_format="text", extended_dns=False):
        if output_format == "json":
            # Prepare JSON output
            # Convert the sorted records to a JSON-friendly format
            json_friendly_sorted_records = {}
            if 'sorted_records' in dns_info:
                for record_type, records in dns_info['sorted_records'].items():
                    json_friendly_sorted_records[record_type] = [
                        {"value": value, "referenced": is_referenced} 
                        for value, is_referenced in records
                    ]
            
            # Create a copy of dns_info without the full sorted_records and dns_summary
            dns_info_json = {k: v for k, v in dns_info.items() 
                             if k not in ('sorted_records', 'dns_summary')}
            
            # Add the JSON-friendly sorted records
            dns_info_json['dns_records_with_references'] = json_friendly_sorted_records
            
            output_data = {
                "domain": domain,
                "whois": whois_info,
                "dns": dns_info_json,
                "virustotal": vt_info,
                "newly_registered": is_new_domain
            }
            
            # Print JSON to console
            print(json.dumps(output_data, indent=4))
            
        elif output_format == "csv":
            # Prepare CSV output
            csv_file = f"{domain}_whois_dns_info.csv"
            with open(csv_file, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                
                # Write header
                writer.writerow(["Category", "Detail"])
                
                # Write WHOIS information
                writer.writerow(["WHOIS Information", ""])
                for key, value in whois_info.items():
                    writer.writerow([key, value])
                
                # Write DNS information
                writer.writerow(["DNS Information", ""])
                for key, value in dns_info.items():
                    if isinstance(value, list):
                        writer.writerow([key, ", ".join(str(item) for item in value)])
                    elif isinstance(value, dict):
                        writer.writerow([key, json.dumps(value)])
                    else:
                        writer.writerow([key, value])
                
                # Write VirusTotal information
                writer.writerow(["VirusTotal Information", ""])
                for key, value in vt_info.items():
                    if isinstance(value, dict):
                        writer.writerow([key, json.dumps(value)])
                    else:
                        writer.writerow([key, value])
            
            print(f"Results saved to {csv_file}")
        
        else:
            # Default to text output
            print("=== WHOIS Information ===")
            print(f"Domain name: {whois_info['domain']}")
            print(f"Registrar: {whois_info['registrar']}")
            print(f"Whois server: {whois_info['whois_server']}")
            if is_new_domain:
                print(f"Creation date: {whois_info['creation_date']} [RECENT REGISTRATION]")
            else:
                print(f"Creation date: {whois_info['creation_date']}")
            print(f"Expiration date: {whois_info['expiration_date']}")
            print(f"Update date: {whois_info['updated_date']}")
            print(f"DNSSEC: {whois_info['dnssec']}")
            print("\n=== DNS Information ===")
            if extended_dns:
                # Print DNS Records Summary if available
                if dns_info.get('dns_summary'):
                    print(dns_info['dns_summary'])
                # Show TXT records only in extended DNS mode
                print(f"\nTXT Records for {domain}:")
                if dns_info['txt_records']:
                    for record in dns_info['txt_records']:
                        print(f"  {record}")
                else:
                    print("  None found")
            else:
                # Only show NS records and their authority/forwarding status
                print(f"\nName servers for {domain}:")
                if dns_info['name_servers']:
                    for ns in dns_info['name_servers']:
                        server_type = check_dns_server_type(domain, ns)
                        print(f"  {ns} - {server_type}")
                else:
                    print("  None listed")
        
        # Display MX records
        print(f"\nMX Records for {domain}:")
        if dns_info['mx_records']:
            for record in dns_info['mx_records']:
                print(f"  {record}")
        else:
            print("  None found")
        
        # Display additional DNS records
        if extended_dns:
            # SRV Records
            if dns_info.get('srv_records'):
                print(f"\nSRV Records for {domain}:")
                if dns_info['srv_records']:
                    for record in dns_info['srv_records']:
                        print(f"  {record}")
                else:
                    print("  None found")
                    
            # CAA Records
            if dns_info.get('caa_records'):
                print(f"\nCAA Records for {domain}:")
                if dns_info['caa_records']:
                    for record in dns_info['caa_records']:
                        print(f"  {record}")
                else:
                    print("  None found")
                
            # SOA Record
            if dns_info.get('soa_record'):
                print(f"\nSOA Record for {domain}:")
                if dns_info['soa_record']:
                    soa = dns_info['soa_record']
                    print(f"  Primary nameserver: {soa['mname']}")
                    print(f"  Admin email: {soa['rname']}")
                    print(f"  Serial: {soa['serial']}")
                    print(f"  Refresh: {soa['refresh']} seconds")
                    print(f"  Retry: {soa['retry']} seconds")
                    print(f"  Expire: {soa['expire']} seconds")
                    print(f"  Minimum TTL: {soa['minimum']} seconds")
                else:
                    print("  None found")
                
            # DNSKEY Records
            if dns_info.get('dnskey_records'):
                print(f"\nDNSKEY Records for {domain}:")
                if dns_info['dnskey_records']:
                    for record in dns_info['dnskey_records']:
                        print(f"  {record}")
                else:
                    print("  None found")
        
        # If this is a subdomain, also show its TXT records if available
        if dns_info.get('subdomain_txt_records'):
            hostname = "subdomain" # This is just a placeholder as we don't have the fqdn here
            print(f"\nTXT Records for {hostname}:")
            if not any(record.startswith("Error") for record in dns_info['subdomain_txt_records']):
                for record in dns_info['subdomain_txt_records']:
                    print(f"  {record}")
            else:
                print("  None found")

        # Display VirusTotal results
        print(format_vt_results(vt_info, is_new_domain))

        # Display conclusion about domain status
        print("\n=== Domain Status ===")
        status = whois_info.get('status')
        if status:
            if isinstance(status, list) and status:
                print("Domain appears to be registered and active.")
            elif status:
                print("Domain appears to be registered and active.")
            else:
                print("Domain is registered but may not be active.")
        else:
            print("Limited information available about this domain.")

        # Display warning for new domains
        if is_new_domain:
            print(f"\n⚠️  WARNING: This domain was registered within the last 6 months!")
            print("Recently registered domains are frequently used for malicious purposes.")
            print("Exercise caution when interacting with this domain or its services.")

    if args.batch:
        # Batch mode - process domains from file
        try:
            input_file = Path(args.input)
            if not input_file.exists():
                print(f"Error: Input file '{args.input}' not found")
                sys.exit(1)
            
            with open(input_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            if not domains:
                print("No domains found in input file")
                sys.exit(1)
            
            print(f"Batch processing {len(domains)} domains with {args.threads} threads")
            
            # Process domains in parallel with ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                # Create a partial function with fixed arguments
                from functools import partial
                process_fn = partial(analyze_domain, no_vt=args.no_vt, output_format=args.output, extended_dns=args.extended_dns)
                # Map the function to all domains
                results = list(executor.map(process_fn, domains))
            
            # Count results
            success = results.count(0)
            not_found = results.count(1)
            error = results.count(2)
            
            print(f"\nBatch processing complete: {success} successful, {not_found} not found, {error} errors")
                
        except Exception as e:
            print(f"Error in batch processing: {e}")
            sys.exit(1)
    else:
        # Single domain mode
        exit_code = analyze_domain(args.input, args.no_vt, args.output, args.extended_dns)
        sys.exit(exit_code)
