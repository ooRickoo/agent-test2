#!/usr/bin/env python3
"""
Host Information Script
----------------------
This script takes an IP address or a domain name as input and provides comprehensive information
by combining data from Shodan, AbuseIPDB, and geolocation APIs. It returns details like open ports,
services, threat intelligence, abuse reports, and geographic location for the target.
"""

import sys
import json
import argparse
import shodan
import os
import socket
import ipaddress
import requests
from urllib.parse import urlparse
from datetime import datetime
from dotenv import load_dotenv

def load_api_keys():
    """Load API keys from environment or prompt user"""
    # Look for .env file in the same directory as the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(script_dir, '.env')
    
    if os.path.exists(env_path):
        # Load the .env file explicitly
        print(f"Loading API keys from: {env_path}")
        load_dotenv(env_path)
    else:
        # Fall back to default behavior
        print("No .env file found in script directory, trying default locations")
        load_dotenv()
    
    # Try to get keys from environment variables
    shodan_api_key = os.environ.get("SHODAN_API_KEY")
    abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY")
    
    # Prompt for keys if not found
    if not shodan_api_key:
        shodan_api_key = input("Please enter your Shodan API key: ")
    
    if not abuseipdb_api_key:
        abuseipdb_api_key = input("Please enter your AbuseIPDB API key: ")
    
    return shodan_api_key, abuseipdb_api_key

def is_valid_ip(ip_str):
    """Check if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def get_ip_from_url(url):
    """Extract IP address from a given URL or domain name."""
    try:
        # Make sure we have a URL with a scheme
        if not url.startswith('http'):
            url = 'http://' + url
        
        domain = urlparse(url).netloc
        if not domain:
            domain = url
            
        # Remove port number if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(f"Error resolving {url}: {e}")
        return None

def resolve_domain(domain):
    """Resolve a domain name to an IP address"""
    try:
        # Check if this looks like an invalid IP that was misidentified as a domain
        parts = domain.split('.')
        if len(parts) == 4:
            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    print(f"Warning: '{domain}' looks like an IP address but is not valid.")
                    print("IP addresses must have values between 0-255 in each octet.")
                    return None
            except ValueError:
                pass  # Not a numeric value, so continue treating as domain
                
        ip = socket.gethostbyname(domain)
        print(f"Resolved domain {domain} to IP {ip}")
        return ip
    except socket.gaierror:
        print(f"Error: Could not resolve domain name {domain}")
        return None

def shodan_ip_lookup(ip_address, api_key):
    """Query Shodan for information about an IP address"""
    try:
        # Initialize the Shodan API
        api = shodan.Shodan(api_key)
        
        # Lookup the IP
        results = api.host(ip_address)
        
        # Attempt to get additional threat intel information if available
        try:
            # Some Shodan plans allow for query against threat feeds
            threat_info = api.threatscores.get(ip_address)
            if threat_info and 'score' in threat_info:
                results['threat_score'] = threat_info['score']
                results['threat_details'] = threat_info.get('details', {})
        except (shodan.APIError, AttributeError):
            # This might not be available for all API plans or might be a deprecated feature
            pass
        
        return results
    except shodan.APIError as e:
        print(f"Shodan Error: {e}")
        return None

def lookup_ip_abuseipdb(ip_address, api_key):
    """
    Look up an IP address using the AbuseIPDB API.
    
    API Documentation: https://docs.abuseipdb.com/#check-endpoint
    """
    if not api_key:
        return {"error": "AbuseIPDB API key is required."}
        
    base_url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90,  # Look at reports from the last 90 days
        'verbose': True      # Include verbose details in the response
    }
    
    try:
        response = requests.get(base_url, headers=headers, params=params)
        
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json().get('data', {})
            return data
        elif response.status_code == 401:
            return {"error": "Invalid AbuseIPDB API key. Please check your API key and try again."}
        else:
            return {"error": f"AbuseIPDB API request failed with status code {response.status_code}: {response.text}"}
            
    except requests.RequestException as e:
        return {"error": f"AbuseIPDB request failed: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse AbuseIPDB response"}
    except Exception as e:
        return {"error": f"Unexpected error with AbuseIPDB: {str(e)}"}

def display_abuseipdb_report(data):
    """Process AbuseIPDB report data for integration with host information"""
    if "error" in data:
        print(f"Error from AbuseIPDB: {data['error']}")
        print("Could not retrieve AbuseIPDB threat intelligence.")
        return False, {}
    
    # Format the data to be returned for integration
    formatted_data = {
        'ip_address': data.get('ipAddress'),
        'abuse_score': data.get('abuseConfidenceScore'),
        'country': data.get('countryName'),
        'country_code': data.get('countryCode'),
        'isp': data.get('isp'),
        'domain': data.get('domain'),
        'hostname': data.get('hostnames', ['N/A'])[0] if data.get('hostnames') else 'N/A',
        'total_reports': data.get('totalReports', 0),
        'is_whitelisted': data.get('isWhitelisted'),
        'usage_type': data.get('usageType'),
    }
    
    # Process lastReportedAt date
    last_reported = data.get('lastReportedAt')
    if last_reported:
        try:
            # Parse the ISO format date
            date_obj = datetime.fromisoformat(last_reported.replace('Z', '+00:00'))
            formatted_data['last_reported'] = date_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            formatted_data['last_reported'] = last_reported
    else:
        formatted_data['last_reported'] = 'Never'
    
    # Process recent reports
    recent_reports = []
    reports = data.get('reports', [])
    if reports:
        # Map for category codes
        category_map = {
            1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
            4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
            7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
            10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
            13: "VPN IP", 14: "Port Scan", 15: "Hacking",
            16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
            19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
            22: "SSH", 23: "IoT Targeted"
        }
        
        for report in reports[:5]:  # Process up to 5 most recent reports
            report_info = {}
            
            # Process categories
            categories = report.get('categories', [])
            category_names = []
            for cat in categories:
                category_names.append(category_map.get(cat, f"Category {cat}"))
            
            # Process report date
            reported_at = report.get('reportedAt', '')
            try:
                date_obj = datetime.fromisoformat(reported_at.replace('Z', '+00:00'))
                report_info['date'] = date_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
            except:
                report_info['date'] = reported_at
            
            report_info['categories'] = category_names
            report_info['comment'] = report.get('comment')
            
            recent_reports.append(report_info)
        
        formatted_data['recent_reports'] = recent_reports
    
    return True, formatted_data

def geolocate_ip(ip_address):
    """
    Get geolocation data using the free ip-api.com service.
    
    This service has a limit of 45 requests per minute for free usage.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        
        if data.get("status") == "success":
            return {
                "ip": ip_address,
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "timezone": data.get("timezone"),
                "as": data.get("as"),
                "asname": data.get("asname")
            }
        else:
            return {"error": data.get("message", "Unknown error")}
            
    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse response"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def display_results(shodan_results, abuseipdb_data, geo_data=None):
    """Display combined results in a readable format"""
    # Check if we have any data to display
    has_shodan = shodan_results is not None and isinstance(shodan_results, dict)
    has_abuseipdb = isinstance(abuseipdb_data, dict) and len(abuseipdb_data) > 0
    has_geo = isinstance(geo_data, dict) and len(geo_data) > 0 and 'error' not in geo_data
    
    if not has_shodan and not has_abuseipdb and not has_geo:
        print("No information found for this IP address.")
        return
    
    print("\n=== BASIC INFORMATION ===")
    
    # Display IP
    ip_str = None
    if has_shodan:
        ip_str = shodan_results.get('ip_str')
    elif has_abuseipdb:
        ip_str = abuseipdb_data.get('ip_address')
    elif has_geo:
        ip_str = geo_data.get('ip')
    
    print(f"IP: {ip_str if ip_str else 'N/A'}")
    
    # Display Organization
    org = None
    if has_shodan:
        org = shodan_results.get('org')
    elif has_geo:
        org = geo_data.get('org')
    elif has_abuseipdb and abuseipdb_data.get('isp'):
        org = abuseipdb_data.get('isp')  # Use ISP as org if that's all we have
    
    print(f"Organization: {org if org else 'N/A'}")
    
    # Display ISP
    isp = None
    if has_shodan:
        isp = shodan_results.get('isp')
    elif has_abuseipdb:
        isp = abuseipdb_data.get('isp')
    elif has_geo:
        isp = geo_data.get('isp')
    
    print(f"ISP: {isp if isp else 'N/A'}")
    
    # Display Hostname
    hostname = None
    if has_shodan:
        hostnames = shodan_results.get('hostnames', [])
        if hostnames:
            hostname = ', '.join(hostnames)
    elif has_abuseipdb:
        hostname = abuseipdb_data.get('hostname')
    
    print(f"Hostname(s): {hostname if hostname else 'N/A'}")
    
    # Display Country
    country = None
    if has_shodan:
        country = shodan_results.get('country_name')
    elif has_abuseipdb:
        country = abuseipdb_data.get('country')
    elif has_geo:
        country = geo_data.get('country')
    
    country_code = None
    if has_shodan and shodan_results.get('country_code'):
        country_code = shodan_results.get('country_code')
    elif has_abuseipdb:
        country_code = abuseipdb_data.get('country_code')
    elif has_geo:
        country_code = geo_data.get('country_code')
    
    if country and country_code:
        print(f"Country: {country} ({country_code})")
    elif country:
        print(f"Country: {country}")
    else:
        print("Country: N/A")
    
    # Display City
    city = None
    if has_shodan:
        city = shodan_results.get('city')
    elif has_geo:
        city = geo_data.get('city')
    
    print(f"City: {city if city else 'N/A'}")
    
    # Display region if available from geo data
    if has_geo and geo_data.get('region'):
        print(f"Region: {geo_data.get('region')}")
        
    # Display coordinates if available from geo data
    if has_geo and geo_data.get('latitude') and geo_data.get('longitude'):
        print(f"Coordinates: {geo_data.get('latitude')}, {geo_data.get('longitude')}")
        
    # Display ASN info if available
    asn = None
    asname = None
    if has_shodan:
        asn = shodan_results.get('asn')
    elif has_geo:
        asn = geo_data.get('as')
        asname = geo_data.get('asname')
    
    if asn:
        print(f"ASN: {asn}")
        if asname:
            print(f"AS Name: {asname}")
    
    # Add Integrated Threat Intelligence section
    print("\n=== THREAT INTELLIGENCE ===")
    
    malicious = False
    
    # Display AbuseIPDB information if available
    if has_abuseipdb:
        print("\n----- AbuseIPDB Report -----")
        print(f"Abuse Confidence Score: {abuseipdb_data.get('abuse_score')}%")
        print(f"Total Reports: {abuseipdb_data.get('total_reports', 0)}")
        print(f"Last Reported: {abuseipdb_data.get('last_reported', 'Never')}")
        print(f"Usage Type: {abuseipdb_data.get('usage_type', 'N/A')}")
        
        # Detect malicious status from AbuseIPDB
        if abuseipdb_data.get('abuse_score', 0) > 25:
            malicious = True
        
        # Display whitelist status
        if abuseipdb_data.get('is_whitelisted') is True:
            print("IP Status: Whitelisted in AbuseIPDB")
        elif abuseipdb_data.get('is_whitelisted') is False:
            print("IP Status: Not whitelisted in AbuseIPDB")
            
        # Display recent reports if available
        recent_reports = abuseipdb_data.get('recent_reports', [])
        if recent_reports:
            print("\nMost Recent Reports:")
            for i, report in enumerate(recent_reports, 1):
                cat_str = ', '.join(report.get('categories', []))
                print(f"  {i}. [{report.get('date', 'Unknown date')}] {cat_str}")
                if report.get('comment'):
                    print(f"     Comment: {report.get('comment')}")
    
    # Show Shodan Intelligence if available
    if has_shodan:
        print("\n----- Shodan Intelligence -----")
        # Display Shodan tags
        tags = shodan_results.get('tags', [])
        if tags:
            print("Tags:")
            for tag in tags:
                print(f"- {tag}")
        else:
            print("No specific threat tags identified in Shodan")
        
        # Check for malicious indicators
        # Checking if IP is flagged in any known malicious lists
        if shodan_results.get('malware', {}).get('count', 0) > 0:
            print("\nMalware Information:")
            malware = shodan_results.get('malware', {}).get('results', [])
            for item in malware:
                print(f"- Source: {item.get('source', 'N/A')}")
                print(f"  Type: {item.get('type', 'N/A')}")
                print(f"  Timestamp: {item.get('timestamp', 'N/A')}")
            malicious = True
        
        # Check if the host has been observed as part of any botnet
        botnet_indicators = [s for s in shodan_results.get('data', []) if 'botnet' in str(s).lower()]
        if botnet_indicators:
            print("\nBotnet Indicators:")
            for indicator in botnet_indicators:
                print(f"- {indicator.get('_shodan', {}).get('module', 'Unknown module')}: {indicator.get('port', 'N/A')}")
            malicious = True
            
        # Check for honeypot score if available
        if 'honeyscore' in shodan_results:
            score = shodan_results['honeyscore']
            print(f"\nHoneypot Score: {score}/1.0 (Higher scores indicate likely honeypot)")
            if score > 0.5:
                print("Warning: This may be a honeypot system")
        
        # Check for scanning activity (IPs known to scan others)
        if tags and any(tag.lower() in ['scanner', 'scanning', 'scan'] for tag in tags):
            print("\nScanning Activity: This host has been identified as performing scanning activity")
            malicious = True
        
        # Display threat score if available
        if 'threat_score' in shodan_results:
            score = shodan_results['threat_score']
            print(f"\nThreat Score: {score}/100")
            if score > 70:
                print("CRITICAL: This IP is highly likely to be malicious")
                malicious = True
            elif score > 40:
                print("WARNING: This IP shows moderate indicators of malicious activity")
                malicious = True
            elif score > 10:
                print("LOW: This IP shows minor indicators of suspicious activity")
        
        # Add any additional threat details available
        if shodan_results.get('threat_details'):
            print("\nThreat Details:")
            for source, info in shodan_results.get('threat_details', {}).items():
                print(f"- {source}: {info}")
    
    # Show geolocation information if available and Shodan is not
    elif has_geo and not has_shodan:
        print("\n----- Geolocation Information -----")
        if geo_data.get('asname'):
            print(f"AS Name: {geo_data.get('asname')}")
        if geo_data.get('timezone'):
            print(f"Timezone: {geo_data.get('timezone')}")
    
    # Check for cloud provider (not necessarily malicious but useful context)
    cloud_providers = ['aws', 'amazon', 'azure', 'microsoft', 'google', 'oracle', 'digitalocean', 'linode', 'cloudflare']
    org_str = ""
    
    if has_shodan:
        org_str = str(shodan_results.get('org', '')).lower()
    elif has_geo:
        org_str = str(geo_data.get('org', '')).lower()
    elif has_abuseipdb:
        org_str = str(abuseipdb_data.get('isp', '')).lower()
    
    if org_str and any(provider in org_str for provider in cloud_providers):
        cloud_name = next((provider for provider in cloud_providers if provider in org_str), None)
        print(f"\nCloud Provider: This appears to be a {cloud_name.upper() if cloud_name else 'cloud'} hosted IP address")
    
    # Summary of threat intelligence
    print("\n----- Threat Summary -----")
    if has_abuseipdb and abuseipdb_data.get('abuse_score', 0) > 0:
        print(f"AbuseIPDB Score: {abuseipdb_data.get('abuse_score')}% confidence of abuse")
    
    if malicious:
        print("ALERT: This IP address shows indicators of malicious activity")
    elif not has_shodan and not has_abuseipdb:
        print("No threat intelligence information available")
    else:
        print("No explicit malicious indicators found")
    
    # Only show port and service information if Shodan data is available
    if has_shodan:
        print("\n=== OPEN PORTS ===")
        ports = shodan_results.get('ports', [])
        if ports:
            for port in ports:
                print(f"- {port}")
        else:
            print("No open ports detected")
        
        print("\n=== SERVICES ===")
        services = shodan_results.get('data', [])
        if services:
            for service in services:
                print(f"\nPort: {service.get('port', 'N/A')}")
                print(f"Protocol: {service.get('transport', 'N/A')}")
                print(f"Service: {service.get('_shodan', {}).get('module', 'N/A')}")
                
                banner = service.get('data', '').strip()
                if banner:
                    # Limit the banner to prevent overflow
                    if len(banner) > 100:
                        banner = banner[:100] + "..."
                    print(f"Banner: {banner}")
        else:
            print("No detailed service information available")
        
        # Print any available vulnerabilities
        vulns = shodan_results.get('vulns', [])
        if vulns:
            print("\n=== VULNERABILITIES ===")
            for vuln in vulns:
                print(f"- {vuln}")
        
        # Print SSL/TLS information if available
        ssl_services = [s for s in shodan_results.get('data', []) if 'ssl' in s]
        if ssl_services:
            print("\n=== SSL/TLS INFORMATION ===")
            for service in ssl_services:
                ssl_info = service.get('ssl', {})
                print(f"\nPort: {service.get('port', 'N/A')}")
                if 'cert' in ssl_info:
                    cert = ssl_info['cert']
                    print(f"  Subject: {cert.get('subject', {}).get('CN', 'N/A')}")
                    print(f"  Issuer: {cert.get('issuer', {}).get('CN', 'N/A')}")
                    print(f"  Expiry: {cert.get('expires', 'N/A')}")
                if 'versions' in ssl_info:
                    print(f"  Supported Versions: {', '.join(ssl_info['versions'])}")
                if 'cipher' in ssl_info:
                    print(f"  Cipher: {ssl_info['cipher'].get('name', 'N/A')}")
    elif has_abuseipdb or has_geo:
        print("\nNote: Port/service scan information not available. Use Shodan API for port and service details.")
    
    # Show additional information from any source
    print("\n=== ADDITIONAL INFO ===")
    
    # Show domain information
    domain_info = None
    if has_shodan:
        domain_info = shodan_results.get('domains')
    elif has_abuseipdb:
        domain_info = abuseipdb_data.get('domain')
    
    if domain_info:
        if isinstance(domain_info, list):
            print(f"Domains: {', '.join(domain_info) if domain_info else 'N/A'}")
        else:
            print(f"Domain: {domain_info}")
    else:
        print("Domain: N/A")
    
    # Show last update info if available
    if has_shodan:
        print(f"Last Update: {shodan_results.get('last_update', 'N/A')}")
    
    # Show timezone if available from geo data
    if has_geo and geo_data.get('timezone'):
        print(f"Timezone: {geo_data.get('timezone')}")
        
    # Additional geolocation details if available
    if has_geo:
        if geo_data.get('asname'):
            print(f"AS Name: {geo_data.get('asname')}")
            
    if not has_shodan:
        print("\nNote: For more detailed port and service information, try using the Shodan API.")

def main():
    parser = argparse.ArgumentParser(description="Get comprehensive host information from multiple sources")
    parser.add_argument("target", nargs="?", help="The IP address or domain name to look up")
    parser.add_argument("-k", "--shodan-key", help="Shodan API key")
    parser.add_argument("-a", "--abuseipdb-key", help="AbuseIPDB API key")
    parser.add_argument("-j", "--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--shodan-only", action="store_true", help="Only use Shodan for lookups")
    parser.add_argument("--abuseipdb-only", action="store_true", help="Only use AbuseIPDB for lookups")
    
    args = parser.parse_args()
    
    # If no IP or domain is provided, use the current IP
    if not args.target:
        print("No IP address or domain provided, getting your current IP information...")
        try:
            response = requests.get("https://api.ipify.org?format=json")
            target = response.json()["ip"]
            print(f"Using current IP: {target}")
        except Exception as e:
            print(f"Error getting current IP: {e}")
            sys.exit(1)
    else:
        target = args.target
    
    # Get API keys if not provided
    shodan_key, abuseipdb_key = None, None
    
    if not args.abuseipdb_only:
        shodan_key = args.shodan_key or os.environ.get("SHODAN_API_KEY")
    
    if not args.shodan_only:
        abuseipdb_key = args.abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY")
    
    if not shodan_key and not abuseipdb_key:
        shodan_key, abuseipdb_key = load_api_keys()
    
    if not shodan_key and not args.abuseipdb_only:
        print("Error: No Shodan API key provided")
        sys.exit(1)
    
    if not abuseipdb_key and not args.shodan_only:
        print("Error: No AbuseIPDB API key provided")
        sys.exit(1)
    
    # Check if the input is a domain name or IP address and get IP
    if is_valid_ip(target):
        ip_address = target
    else:
        # Try to validate if this could be a domain
        if "." in target and not any(c.isspace() for c in target) and len(target) < 255:
            print(f"Input appears to be a domain name: {target}")
            ip_address = resolve_domain(target)
            if not ip_address:
                print("Could not resolve the domain name. Exiting.")
                sys.exit(1)
        else:
            print(f"Error: '{target}' is not a valid IP address or domain name.")
            print("Please provide a valid IPv4/IPv6 address or a resolvable domain name.")
            sys.exit(1)
    
    # Initialize results
    shodan_results = None
    abuseipdb_data = {}
    geo_data = None
    combined_json = {}
    
    print(f"Looking up information for: {ip_address}")
    
    # Always get geolocation data as a reliable fallback
    print("Retrieving geolocation data...")
    geo_data = geolocate_ip(ip_address)
    if geo_data and 'error' not in geo_data and args.json:
        combined_json["geolocation"] = geo_data
    
    # Query Shodan if not using AbuseIPDB only
    if not args.abuseipdb_only and shodan_key:
        print("Querying Shodan database...")
        shodan_results = shodan_ip_lookup(ip_address, shodan_key)
        if shodan_results and args.json:
            combined_json["shodan"] = shodan_results
        elif not shodan_results:
            print("No information found in Shodan database.")
    
    # Query AbuseIPDB if not using Shodan only
    if not args.shodan_only and abuseipdb_key:
        print("Querying AbuseIPDB...")
        abuse_data = lookup_ip_abuseipdb(ip_address, abuseipdb_key)
        success, abuseipdb_data = display_abuseipdb_report(abuse_data)
        if success and args.json:
            combined_json["abuseipdb"] = abuse_data
        elif not success:
            print("No information found in AbuseIPDB.")
            
    # Display results
    if args.json:
        if combined_json:
            print(json.dumps(combined_json, indent=2))
        else:
            print("{}")
    else:
        if args.abuseipdb_only and abuseipdb_key:
            # Only display AbuseIPDB information
            print(f"\n=== ABUSEIPDB LOOKUP RESULTS FOR: {target} ===")
            if target != ip_address:
                print(f"Resolved IP: {ip_address}")
            display_abuse_report(abuse_data)
        elif args.shodan_only and shodan_key:
            # Only display Shodan information
            print(f"\n=== SHODAN LOOKUP RESULTS FOR: {target} ===")
            if target != ip_address:
                print(f"Resolved IP: {ip_address}")
            # Even in Shodan-only mode, include geo data as fallback
            display_results(shodan_results, {}, geo_data)
        else:
            # Display combined information from all available sources
            print(f"\n=== HOST INFORMATION FOR: {target} ===")
            if target != ip_address:
                print(f"Resolved IP: {ip_address}")
            
            # Always display whatever data we have available
            has_any_data = (shodan_results is not None) or abuseipdb_data or (geo_data and 'error' not in geo_data)
            
            if has_any_data:
                display_results(shodan_results, abuseipdb_data, geo_data)
            else:
                print(f"No results found for {target} from any data source.")
                sys.exit(1)

# Display the stand-alone AbuseIPDB report format (for abuseipdb-only mode)
def display_abuse_report(data):
    """Display AbuseIPDB report data in a readable format."""
    if "error" in data:
        print(f"Error: {data['error']}")
        return
        
    print("\n==== AbuseIPDB Report ====")
    print(f"IP Address: {data.get('ipAddress')}")
    print(f"Abuse Score: {data.get('abuseConfidenceScore')}%")
    print(f"Country: {data.get('countryName')} ({data.get('countryCode', '')})")
    print(f"ISP: {data.get('isp', 'N/A')}")
    print(f"Domain: {data.get('domain', 'N/A')}")
    print(f"Hostname: {data.get('hostnames', ['N/A'])[0] if data.get('hostnames') else 'N/A'}")
    print(f"Total Reports: {data.get('totalReports', 0)}")
    
    # Create a time string from lastReportedAt
    last_reported = data.get('lastReportedAt')
    if last_reported:
        try:
            # Parse the ISO format date
            date_obj = datetime.fromisoformat(last_reported.replace('Z', '+00:00'))
            last_reported = date_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            pass  # Keep the original string if parsing fails
    print(f"Last Reported: {last_reported if last_reported else 'Never'}")
    
    print(f"Usage Type: {data.get('usageType', 'N/A')}")
    
    # Display the most recent reports if available
    reports = data.get('reports', [])
    if reports:
        print("\nMost Recent Reports:")
        for i, report in enumerate(reports[:5], 1):  # Show up to 5 most recent reports
            categories = report.get('categories', [])
            category_names = []
            for cat in categories:
                # Map category codes to human-readable names (based on AbuseIPDB API documentation)
                category_map = {
                    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
                    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
                    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
                    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
                    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
                    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
                    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
                    22: "SSH", 23: "IoT Targeted"
                }
                category_names.append(category_map.get(cat, f"Category {cat}"))
            
            reported_at = report.get('reportedAt', '')
            try:
                date_obj = datetime.fromisoformat(reported_at.replace('Z', '+00:00'))
                reported_at = date_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
            except:
                pass
                
            print(f"  {i}. [{reported_at}] {', '.join(category_names)}")
            if report.get('comment'):
                print(f"     Comment: {report.get('comment')}")
    
    # Display whitelisted status
    if data.get('isWhitelisted') is True:
        print("\nThis IP is whitelisted in AbuseIPDB")
    elif data.get('isWhitelisted') is False:
        print("\nThis IP is not whitelisted in AbuseIPDB")
        
    print("==========================\n")

if __name__ == "__main__":
    main()
