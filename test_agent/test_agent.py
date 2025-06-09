import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dotenv import load_dotenv
import re
import socket
import ipaddress
import whois
import dns.resolver
import requests
import time

# Add secure_agent_lib to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'secure_agent_lib'))

# Add the project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from secure_agent_lib.examples.public_api_example import PublicAPIAgent
from secure_agent_lib.examples.cybertools_agent import CybertoolsAgent
from secure_agent_lib.config.base_config import (
    AgentConfig,
    LoggingConfig,
    SecurityConfig,
    ValidationConfig,
    APIConfig
)
from secure_agent_lib.core.base_agent import BaseAgent
import json
from typing import Dict, Any
import anthropic
import requests

# Configure logging
logging.basicConfig(
    filename='security_agent.log',
    level=logging.INFO,
    format='%(message)s'
)

def get_user_input():
    """Get user input for security analysis"""
    print("\n=== Security Analysis Tool ===")
    print("What would you like to analyze?")
    print("Examples:")
    print("  - Check the security status of 8.8.8.8")
    print("  - What can you tell me about example.com?")
    print("  - Analyze the security posture of data-gadgets.com")
    print("\nEnter your query (or 'quit' to exit):")
    return input("> ").strip()

def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def is_internal_domain(domain: str) -> bool:
    """Check if a domain is internal or related to rickonsecurity.com."""
    internal_domains = [
        'rickonsecurity.com',
        'localhost',
        'local',
        'internal',
        'intranet',
        'corp',
        'home',
        'lan',
        'localdomain'
    ]
    return any(internal in domain.lower() for internal in internal_domains)

def get_domain_age(domain: str, soa_serial: Optional[int] = None) -> tuple[bool, str]:
    """Get domain age using WHOIS and SOA serial as fallback."""
    try:
        # Try WHOIS first
        print(f"\nAttempting WHOIS lookup for {domain}...")
        try:
            w = whois.whois(domain)
            print(f"WHOIS response: {w}")
            
            if w and w.creation_date:
                # Handle both single date and list of dates
                if isinstance(w.creation_date, list):
                    # Sort dates and take the earliest one
                    creation_date = sorted(w.creation_date)[0]
                else:
                    creation_date = w.creation_date
                
                current_date = datetime.now()
                age = current_date - creation_date
                is_new = age.days < 30
                age_str = f"{age.days} days"
                print(f"Domain age from WHOIS: {age_str}")
                return is_new, age_str
            else:
                print("No creation date found in WHOIS response")
        except Exception as e:
            error_msg = str(e)
            print(f"WHOIS lookup failed: {error_msg}")
            if "No match for domain" in error_msg:
                print("Domain does not exist or is not registered")
            elif "Connection refused" in error_msg:
                print("WHOIS server connection refused - please try again later")
            elif not error_msg:
                print("WHOIS lookup failed with no error message - please try again later")
            else:
                print(f"Unexpected WHOIS error: {error_msg}")
                # Add more detailed error logging
                print("This could be due to:")
                print("- WHOIS server being temporarily unavailable")
                print("- Rate limiting from the WHOIS server")
                print("- Network connectivity issues")
                print("- Domain registrar not providing WHOIS data")
    except Exception as e:
        error_msg = str(e)
        print(f"WHOIS lookup failed: {error_msg}")
        if not error_msg:
            print("WHOIS lookup failed with no error message - please try again later")
            print("This could be due to:")
            print("- WHOIS server being temporarily unavailable")
            print("- Rate limiting from the WHOIS server")
            print("- Network connectivity issues")
            print("- Domain registrar not providing WHOIS data")
    
    # Fallback to SOA serial if WHOIS fails
    if soa_serial:
        try:
            print(f"\nFalling back to SOA serial: {soa_serial}")
            serial_str = str(soa_serial)
            
            # Try Unix timestamp format first (common for many DNS providers)
            try:
                # Check if it's a Unix timestamp (seconds since epoch)
                if len(serial_str) == 10:  # Standard Unix timestamp length
                    domain_date = datetime.fromtimestamp(int(serial_str))
                    current_date = datetime.now()
                    age = current_date - domain_date
                    is_new = age.days < 30
                    age_str = f"{age.days} days"
                    print(f"Domain age from SOA (Unix timestamp): {age_str}")
                    return is_new, age_str
            except (ValueError, OSError):
                pass
            
            # Try different SOA serial formats
            if len(serial_str) >= 8:
                # Format: YYYYMMDDnn
                year = int(serial_str[:4])
                month = int(serial_str[4:6])
                day = int(serial_str[6:8])
                domain_date = datetime(year, month, day)
            elif len(serial_str) >= 6:
                # Format: YYMMDDnn
                year = 2000 + int(serial_str[:2])  # Assume 20xx
                month = int(serial_str[2:4])
                day = int(serial_str[4:6])
                domain_date = datetime(year, month, day)
            else:
                # Format: Unix timestamp or other
                print(f"Unrecognized SOA serial format: {serial_str}")
                return False, "Unknown"
            
            current_date = datetime.now()
            age = current_date - domain_date
            is_new = age.days < 30
            age_str = f"{age.days} days"
            print(f"Domain age from SOA: {age_str}")
            return is_new, age_str
        except (ValueError, IndexError) as e:
            print(f"Error parsing SOA serial: {str(e)}")
            pass
    
    print("Could not determine domain age")
    return False, "Unknown"

def format_datetime(dt) -> str:
    """Format datetime object or list of datetime objects into a readable string."""
    if isinstance(dt, list):
        # Sort dates and take the earliest one
        dt = sorted(dt)[0]
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(dt)

def collect_tool_outputs(result: Dict[str, Any], agent_name: str) -> str:
    """Collect and format tool outputs from the agent's result."""
    if not result or 'tool_outputs' not in result:
        return f"No results from {agent_name}"
    
    outputs = []
    for tool_name, tool_result in result['tool_outputs'].items():
        if tool_result and isinstance(tool_result, dict):
            if 'error' in tool_result:
                outputs.append(f"{tool_name}: Error - {tool_result['error']}")
            else:
                outputs.append(f"{tool_name}: {tool_result.get('result', 'No data')}")
    
    return "\n".join(outputs) if outputs else f"No results from {agent_name}"

def summarize_with_ai(data: str, query: str) -> str:
    """Summarize the collected data using AI."""
    # This is a placeholder for AI summarization
    return f"Based on the analysis of {query}, here are the key findings:\n{data}"

def process_query(query: str, public_api_agent: PublicAPIAgent, cybertools_agent: CybertoolsAgent) -> None:
    """Process a user query using both agents."""
    print("\n=== Starting Comprehensive Security Analysis ===")
    print("This analysis will use multiple security tools and sources to provide a complete assessment.")
    
    # Extract domain or IP from query
    domain_match = re.search(r'([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,})[^a-zA-Z0-9-]?', query)
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
    
    entity = None
    entity_type = None
    
    if domain_match:
        # Clean up the domain by removing any trailing punctuation
        entity = domain_match.group(1).rstrip('?.,!;:')
        entity_type = "domain"
        if is_internal_domain(entity):
            print("\n❌ Access Denied: This agent can only analyze public internet resources.")
            print("The requested domain appears to be internal or related to rickonsecurity.com.")
            return
    elif ip_match:
        entity = ip_match.group(0)
        entity_type = "ip"
        if is_private_ip(entity):
            print("\n❌ Access Denied: This agent can only analyze public internet resources.")
            print("The requested IP address is private/internal.")
            return
    
    # Initialize list to store all tool outputs
    all_tool_outputs = []
    
    # Process with PublicAPIAgent if we have an entity
    if entity:
        print("\n=== Phase 1: Threat Intelligence Analysis ===")
        print("Analyzing using VirusTotal, AbuseIPDB, Shodan, and Geolocation...")
        
        result = public_api_agent.process_input(query, {})
        tool_outputs = collect_tool_outputs(result, "PublicAPIAgent")
        
        if tool_outputs:
            print("\n📊 Threat Intelligence Results:")
            print(tool_outputs)
            all_tool_outputs.append(tool_outputs)
    
    # Phase 2: Use CybertoolsAgent for additional analysis
    if entity:
        print("\n=== Phase 2: Additional Tool Analysis (CybertoolsAgent) ===")
        result2 = cybertools_agent.process_input(query)
        if not result2.get('success'):
            print(result2.get('message', 'No additional results.'))
        else:
            # Get applicable tools
            tools = cybertools_agent._get_applicable_tools(result2['entity_type'])
            tool_results = []
            for tool in tools:
                tool_result = cybertools_agent.execute_tool(
                    tool['tool'],
                    command=tool['command']
                )
                tool_results.append(tool_result)
            # Analyze results
            analysis = cybertools_agent._analyze_results(tool_results, result2['entity'])
            print("\nCybertoolsAgent Analysis:")
            print(analysis)
    
    # If we have a domain, analyze it regardless of external API results
    if entity_type == "domain":
        print("\n=== Phase 2: Domain Analysis ===")
        domain = entity
        soa_serial = None  # Initialize soa_serial to None
        dns_records = {}  # Initialize dns_records as an empty dictionary
        resolved_ip = None  # Initialize resolved_ip to None
        public_api_results = []  # Initialize public_api_results as an empty list
        is_new, age_str = get_domain_age(domain, soa_serial)
        print(f"\n=== Domain Information for {domain} ===\n")
        print("=== DNS Records ===\n")
        for record_type, records in dns_records.items():
            if records:
                print(f"{record_type} Records:")
                for record in records:
                    print(record)
                print()
        print(f"Resolved IP: {resolved_ip}\n")
        # Only show warning if domain age is known and less than 30 days old
        age_days = 0 if age_str == 'Unknown' else int(age_str.split()[0])
        if age_str != 'Unknown' and age_days < 30:
            print("⚠️ SECURITY WARNING: This domain is only {} old!".format(age_str))
            print("New domains (less than 30 days old) are often used for malicious purposes such as:")
            print("- Phishing campaigns")
            print("- Malware distribution")
            print("- Spam operations")
            print("- Command and control servers")
            print("- Fraudulent websites")
            print("\nExercise extreme caution when interacting with this domain.\n")
        all_tool_outputs.append(f"⚠️ SECURITY WARNING: This domain is only {age_str} old!")
        all_tool_outputs.append("New domains (less than 30 days old) are often used for malicious purposes such as:")
        all_tool_outputs.append("- Phishing campaigns")
        all_tool_outputs.append("- Malware distribution")
        all_tool_outputs.append("- Spam operations")
        all_tool_outputs.append("- Command and control servers")
        all_tool_outputs.append("- Fraudulent websites")
        all_tool_outputs.append("\nExercise extreme caution when interacting with this domain.")
    
    # If we have an IP address, also use the cybertools
    elif entity_type == "ip":
        print("\n=== Phase 2: Additional IP Analysis ===")
        ip = entity
        
        try:
            # Get geolocation data
            geo_data = geolocate_ip_ipapi(ip)
            if "error" not in geo_data:
                geo_output = f"""=== Detailed Geolocation Information ===
IP: {ip}
Country: {geo_data.get('country', 'N/A')}
Region: {geo_data.get('region', 'N/A')}
City: {geo_data.get('city', 'N/A')}"""
                if "latitude" in geo_data and "longitude" in geo_data:
                    geo_output += f"\nCoordinates: {geo_data['latitude']}, {geo_data['longitude']}"
                geo_output += f"\nISP: {geo_data.get('isp', 'N/A')}"
                geo_output += f"\nTimezone: {geo_data.get('timezone', 'N/A')}"
                print(f"\n{geo_output}")
                all_tool_outputs.append(geo_output)
        except Exception as e:
            print(f"\nError getting geolocation data: {str(e)}")
        
        try:
            # Get host information
            shodan_key = os.getenv('SHODAN_API_KEY')
            abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
            
            if shodan_key and abuseipdb_key:
                shodan_results = shodan_ip_lookup(ip, shodan_key)
                abuseipdb_data = lookup_ip_abuseipdb(ip, abuseipdb_key)
                
                if shodan_results or abuseipdb_data:
                    host_output = "\n=== Additional Host Information ==="
                    
                    if shodan_results:
                        shodan_output = "\nShodan Information:"
                        shodan_output += f"\nOrganization: {shodan_results.get('org', 'N/A')}"
                        shodan_output += f"\nISP: {shodan_results.get('isp', 'N/A')}"
                        if "ports" in shodan_results:
                            shodan_output += f"\nOpen Ports: {', '.join(map(str, shodan_results['ports']))}"
                        host_output += shodan_output
                    else:
                        host_output += "\nShodan Error: No information available for that IP."
                    
                    if abuseipdb_data and "error" not in abuseipdb_data:
                        abuse_output = "\nAbuseIPDB Information:"
                        abuse_output += f"\nAbuse Confidence Score: {abuseipdb_data.get('abuseConfidenceScore', 'N/A')}%"
                        abuse_output += f"\nTotal Reports: {abuseipdb_data.get('totalReports', 'N/A')}"
                        abuse_output += f"\nLast Reported: {abuseipdb_data.get('lastReportedAt', 'Never')}"
                        host_output += abuse_output
                    
                    print(host_output)
                    all_tool_outputs.append(host_output)
        except Exception as e:
            print(f"\nError getting host information: {str(e)}")
    
    # Combine all tool outputs for final summarization
    combined_outputs = "\n\n".join(all_tool_outputs) if all_tool_outputs else "No information available"
    
    # Print AI Analysis Summary
    print("\n=== AI Analysis Summary ===")
    print(f"Based on the analysis of {query}, here are the key findings:")
    
    # Add PublicAPIAgent results to summary
    if public_api_results:
        print("\nThreat Intelligence Analysis:")
        for result in public_api_results:
            print(f"- {result}")
    else:
        print("No results from PublicAPIAgent")
    
    # Add domain age warning to summary only if age is known and less than 30 days
    if entity_type == "domain" and age_str != 'Unknown' and age_days < 30:
        print(f"\n⚠️ SECURITY WARNING: This domain is only {age_str} old!")
        print("\nNew domains (less than 30 days old) are often used for malicious purposes such as:")
        print("\n- Phishing campaigns")
        print("\n- Malware distribution")
        print("\n- Spam operations")
        print("\n- Command and control servers")
        print("\n- Fraudulent websites")
        print("\n\nExercise extreme caution when interacting with this domain.")
    
    print("\n=== Analysis Complete ===")
    print("The analysis has been completed using multiple security tools and sources.")
    print("Review both phases above for a comprehensive security assessment.")

def verify_api_key(key_name: str, value: str) -> bool:
    """Verify that an API key is properly formatted"""
    if not value or len(value.strip()) == 0:
        print(f"❌ Error: {key_name} is empty or contains only whitespace")
        return False
        
    # Remove any whitespace
    value = value.strip()
    
    # Check for common issues
    if value.startswith('"') or value.endswith('"'):
        print(f"❌ Error: {key_name} contains quotes. Please remove any quotes around the API key.")
        return False
        
    if value.startswith("'") or value.endswith("'"):
        print(f"❌ Error: {key_name} contains quotes. Please remove any quotes around the API key.")
        return False
        
    if "=" in value:
        print(f"❌ Error: {key_name} contains an equals sign. Please provide only the API key value.")
        return False
        
    return True

def format_result(tool_name: str, data: Dict[str, Any]) -> str:
    """Format the result from a specific tool"""
    if tool_name == 'virustotal':
        attributes = data.get('attributes', {})
        return f"""VirusTotal Analysis:
Entity: {data.get('id')}
Type: {data.get('type')}
AS Owner: {attributes.get('as_owner', 'Unknown')}
Country: {attributes.get('country', 'Unknown')}
Reputation: {attributes.get('reputation', 0)}
Last Analysis Stats:
  - Malicious: {attributes.get('last_analysis_stats', {}).get('malicious', 0)}
  - Suspicious: {attributes.get('last_analysis_stats', {}).get('suspicious', 0)}
  - Undetected: {attributes.get('last_analysis_stats', {}).get('undetected', 0)}
  - Harmless: {attributes.get('last_analysis_stats', {}).get('harmless', 0)}"""
    
    elif tool_name == 'abuseipdb':
        return f"""AbuseIPDB Analysis:
IP Address: {data.get('ipAddress')}
Abuse Confidence Score: {data.get('abuseConfidenceScore')}%
Total Reports: {data.get('totalReports')}
Last Reported: {data.get('lastReportedAt')}
Country: {data.get('countryName')} ({data.get('countryCode')})
ISP: {data.get('isp', 'Unknown')}
Organization: {data.get('organization', 'Unknown')}
Latitude: {data.get('latitude')}
Longitude: {data.get('longitude')}
Timezone: {data.get('timezone')}"""
    
    return f"Unknown tool: {tool_name}"

def generate_ai_summary(domain: str, dns_records: Dict[str, list], whois_info: Dict[str, Any], age: str) -> Dict[str, Any]:
    """Generate a comprehensive AI analysis summary from the collected data."""
    summary = {
        "domain": domain,
        "infrastructure": {},
        "security_indicators": {},
        "recommendations": [],
        "threat_indicators": []
    }
    
    # Analyze DNS Records
    if dns_records:
        # Infrastructure Analysis
        if "A" in dns_records:
            summary["infrastructure"]["ipv4_addresses"] = dns_records["A"]
        if "AAAA" in dns_records:
            summary["infrastructure"]["ipv6_addresses"] = dns_records["AAAA"]
        if "NS" in dns_records:
            summary["infrastructure"]["nameservers"] = dns_records["NS"]
            # Check if using Cloudflare
            if any("cloudflare" in ns.lower() for ns in dns_records["NS"]):
                summary["security_indicators"]["cloudflare_protection"] = True
                summary["recommendations"].append("Domain is protected by Cloudflare's security services")
        
        # Email Configuration
        if "MX" in dns_records:
            summary["infrastructure"]["email_servers"] = dns_records["MX"]
            if any("google" in mx.lower() for mx in dns_records["MX"]):
                summary["security_indicators"]["google_workspace"] = True
                summary["recommendations"].append("Domain uses Google Workspace for email")
        
        # Security Headers and Verification
        if "TXT" in dns_records:
            summary["infrastructure"]["txt_records"] = dns_records["TXT"]
            # Check for Google site verification
            if any("google-site-verification" in txt.lower() for txt in dns_records["TXT"]):
                summary["security_indicators"]["google_verified"] = True
    
    # Domain Age Analysis
    if age and age != "Unknown":
        try:
            age_days = int(age.split()[0])
            if age_days < 30:
                summary["security_indicators"]["new_domain"] = True
                summary["threat_indicators"].append({
                    "type": "new_domain",
                    "severity": "high",
                    "description": "Domain is very new (less than 30 days old)",
                    "potential_risks": [
                        "Phishing attacks",
                        "Malware distribution",
                        "Credential harvesting",
                        "Social engineering"
                    ],
                    "recommendations": [
                        "Exercise extreme caution with this domain",
                        "Verify domain legitimacy through multiple sources",
                        "Monitor for suspicious activity",
                        "Consider blocking access to this domain"
                    ]
                })
            elif age_days < 365:
                summary["security_indicators"]["recent_domain"] = True
                summary["threat_indicators"].append({
                    "type": "recent_domain",
                    "severity": "medium",
                    "description": "Domain is relatively new (less than 1 year old)",
                    "potential_risks": [
                        "Phishing attempts",
                        "Suspicious redirects",
                        "Malicious content hosting"
                    ],
                    "recommendations": [
                        "Verify domain legitimacy",
                        "Monitor for suspicious behavior",
                        "Implement additional security measures"
                    ]
                })
        except (ValueError, IndexError):
            pass
    
    # Check for suspicious domain characteristics
    suspicious_patterns = [
        (r'\d+', "Contains numbers"),
        (r'[_-]', "Contains special characters"),
        (r'[A-Z]', "Contains uppercase letters")
    ]
    
    for pattern, description in suspicious_patterns:
        if re.search(pattern, domain):
            summary["threat_indicators"].append({
                "type": "suspicious_pattern",
                "severity": "medium",
                "description": f"Domain {description}",
                "potential_risks": [
                    "Typosquatting attempts",
                    "Phishing domain mimicry",
                    "Brand impersonation"
                ],
                "recommendations": [
                    "Verify domain legitimacy",
                    "Check for similar legitimate domains",
                    "Monitor for brand impersonation"
                ]
            })
    
    # Generate Overall Security Assessment
    security_score = 0
    security_factors = []
    
    if summary["security_indicators"].get("cloudflare_protection"):
        security_score += 2
        security_factors.append("Protected by Cloudflare")
    
    if summary["security_indicators"].get("google_workspace"):
        security_score += 1
        security_factors.append("Uses Google Workspace")
    
    if summary["security_indicators"].get("google_verified"):
        security_score += 1
        security_factors.append("Google verified")
    
    if not summary["security_indicators"].get("new_domain"):
        security_score += 1
        security_factors.append("Established domain")
    
    summary["security_assessment"] = {
        "score": security_score,
        "factors": security_factors,
        "level": "High" if security_score >= 4 else "Medium" if security_score >= 2 else "Low"
    }
    
    return summary

def analyze_domain(domain: str) -> Dict[str, Any]:
    """Analyze domain using various tools."""
    results = {
        "domain": domain,
        "dns_records": {},
        "whois_info": {},
        "age": None,
        "is_new": False
    }
    
    # DNS Analysis
    print("\n=== DNS Records ===")
    try:
        # A Records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            results["dns_records"]["A"] = [str(r) for r in a_records]
            print(f"A Records: {', '.join(results['dns_records']['A'])}")
        except Exception as e:
            print(f"No A records found: {str(e)}")
            results["dns_records"]["A"] = []

        # AAAA Records
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            results["dns_records"]["AAAA"] = [str(r) for r in aaaa_records]
            print(f"AAAA Records: {', '.join(results['dns_records']['AAAA'])}")
        except Exception as e:
            print(f"No AAAA records found: {str(e)}")
            results["dns_records"]["AAAA"] = []

        # MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results["dns_records"]["MX"] = [str(r) for r in mx_records]
            print(f"MX Records: {', '.join(results['dns_records']['MX'])}")
        except Exception as e:
            print(f"No MX records found: {str(e)}")
            results["dns_records"]["MX"] = []

        # NS Records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            results["dns_records"]["NS"] = [str(r) for r in ns_records]
            print(f"NS Records: {', '.join(results['dns_records']['NS'])}")
        except Exception as e:
            print(f"No NS records found: {str(e)}")
            results["dns_records"]["NS"] = []

        # TXT Records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            results["dns_records"]["TXT"] = [str(r) for r in txt_records]
            print(f"TXT Records: {', '.join(results['dns_records']['TXT'])}")
        except Exception as e:
            print(f"No TXT records found: {str(e)}")
            results["dns_records"]["TXT"] = []

        # SOA Record
        try:
            soa_records = dns.resolver.resolve(domain, 'SOA')
            results["dns_records"]["SOA"] = [str(r) for r in soa_records]
            print(f"SOA Records: {', '.join(results['dns_records']['SOA'])}")
            
            # Extract serial number from SOA for domain age estimation
            if soa_records:
                soa_str = str(soa_records[0])
                serial_match = re.search(r'(\d+)', soa_str)
                if serial_match:
                    soa_serial = int(serial_match.group(1))
                    is_new, age = get_domain_age(domain, soa_serial)
                    results["age"] = age
                    results["is_new"] = is_new
        except Exception as e:
            print(f"No SOA records found: {str(e)}")
            results["dns_records"]["SOA"] = []

        # CNAME Records
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            results["dns_records"]["CNAME"] = [str(r) for r in cname_records]
            print(f"CNAME Records: {', '.join(results['dns_records']['CNAME'])}")
        except Exception as e:
            print(f"No CNAME records found: {str(e)}")
            results["dns_records"]["CNAME"] = []

    except Exception as e:
        print(f"Error during DNS analysis: {str(e)}")
        print("This could be due to:")
        print("- Domain does not exist")
        print("- DNS server issues")
        print("- Network connectivity problems")
        print("- DNS resolution timeout")

    # WHOIS Analysis
    print("\n=== WHOIS Information ===")
    try:
        w = whois.whois(domain)
        if w:
            results["whois_info"] = {
                "registrar": w.registrar,
                "creation_date": format_datetime(w.creation_date),
                "expiration_date": format_datetime(w.expiration_date),
                "last_updated": format_datetime(w.updated_date),
                "name_servers": w.name_servers
            }
            print(f"Registrar: {w.registrar}")
            print(f"Creation Date: {results['whois_info']['creation_date']}")
            print(f"Expiration Date: {results['whois_info']['expiration_date']}")
            print(f"Last Updated: {results['whois_info']['last_updated']}")
            print(f"Name Servers: {', '.join(w.name_servers) if w.name_servers else 'None'}")
            
            # Update domain age if not already set from SOA
            if not results["age"]:
                is_new, age = get_domain_age(domain)
                results["age"] = age
                results["is_new"] = is_new
    except Exception as e:
        print(f"Error during WHOIS lookup: {str(e)}")
        print("This could be due to:")
        print("- WHOIS server being temporarily unavailable")
        print("- Rate limiting from the WHOIS server")
        print("- Network connectivity issues")
        print("- Domain registrar not providing WHOIS data")

    return results

def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """Get geolocation information for an IP address."""
    try:
        # Using ipapi.co for geolocation (free tier available)
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        if response.status_code == 200:
            data = response.json()
            return {
                "country": data.get("country_name"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": data.get("timezone"),
                "isp": data.get("org"),
                "asn": data.get("asn")
            }
    except Exception as e:
        print(f"Error getting geolocation: {str(e)}")
    return {}

def convert_epoch_to_human(epoch_time: int) -> str:
    """Convert epoch timestamp to human readable format."""
    try:
        return datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Invalid timestamp"

def analyze_ip(ip: str) -> Dict[str, Any]:
    """Analyze IP address using various tools."""
    results = {
        "ip": ip,
        "dns_records": {},
        "whois_info": {},
        "security_indicators": {},
        "threat_indicators": [],
        "threat_intelligence": {},
        "geolocation": {}
    }
    
    # Validate IP address
    try:
        ip_obj = ipaddress.ip_address(ip)
        results["ip_type"] = "IPv4" if ip_obj.version == 4 else "IPv6"
    except ValueError:
        results["error"] = "Invalid IP address"
        return results

    # Get geolocation information
    print("\n=== Geolocation Information ===")
    geolocation = get_ip_geolocation(ip)
    results["geolocation"] = geolocation
    
    if geolocation:
        print(f"Location: {geolocation.get('city', 'Unknown')}, {geolocation.get('region', 'Unknown')}, {geolocation.get('country', 'Unknown')}")
        print(f"Coordinates: {geolocation.get('latitude', 'Unknown')}, {geolocation.get('longitude', 'Unknown')}")
        print(f"Timezone: {geolocation.get('timezone', 'Unknown')}")
        print(f"ISP: {geolocation.get('isp', 'Unknown')}")
        print(f"ASN: {geolocation.get('asn', 'Unknown')}")
    
    # VirusTotal Analysis
    print("\n=== VirusTotal Analysis ===")
    try:
        vt = VirusTotalAPI(os.getenv('VT_API_KEY'))
        vt_response = vt.get_ip_report(ip)
        results["threat_intelligence"]["virustotal"] = vt_response
        
        if vt_response:
            # Extract relevant information
            if "data" in vt_response:
                data = vt_response["data"]
                if "attributes" in data:
                    attrs = data["attributes"]
                    
                    # Reputation scores
                    if "last_analysis_stats" in attrs:
                        stats = attrs["last_analysis_stats"]
                        results["security_indicators"]["vt_malicious"] = stats.get("malicious", 0)
                        results["security_indicators"]["vt_suspicious"] = stats.get("suspicious", 0)
                        
                        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                            results["threat_indicators"].append({
                                "type": "virustotal_detection",
                                "severity": "high" if stats.get("malicious", 0) > 0 else "medium",
                                "description": f"Detected by {stats.get('malicious', 0)} security vendors as malicious and {stats.get('suspicious', 0)} as suspicious",
                                "potential_risks": [
                                    "Malware distribution",
                                    "Command and control server",
                                    "Phishing infrastructure",
                                    "Malicious activity"
                                ],
                                "recommendations": [
                                    "Block this IP address",
                                    "Monitor for related activity",
                                    "Investigate associated domains",
                                    "Update security controls"
                                ]
                            })
                    
                    # Categories
                    if "categories" in attrs:
                        results["security_indicators"]["vt_categories"] = attrs["categories"]
                    
                    # Country
                    if "country" in attrs:
                        results["security_indicators"]["country"] = attrs["country"]
                    
                    # ASN
                    if "asn" in attrs:
                        results["security_indicators"]["asn"] = attrs["asn"]
                    
                    # Network
                    if "network" in attrs:
                        results["security_indicators"]["network"] = attrs["network"]
    except Exception as e:
        print(f"Error during VirusTotal analysis: {str(e)}")
    
    # AbuseIPDB Analysis
    print("\n=== AbuseIPDB Analysis ===")
    try:
        abuseipdb = AbuseIPDBAPI(os.getenv('ABUSEIPDB_API_KEY'))
        abuse_response = abuseipdb.get_ip_report(ip)
        results["threat_intelligence"]["abuseipdb"] = abuse_response
        
        if abuse_response:
            if "data" in abuse_response:
                data = abuse_response["data"]
                
                # Abuse score
                if "abuseConfidenceScore" in data:
                    score = data["abuseConfidenceScore"]
                    results["security_indicators"]["abuse_score"] = score
                    
                    if score > 50:
                        results["threat_indicators"].append({
                            "type": "abuseipdb_detection",
                            "severity": "high" if score > 80 else "medium",
                            "description": f"High abuse confidence score: {score}%",
                            "potential_risks": [
                                "Known malicious activity",
                                "Abuse of services",
                                "Attack source"
                            ],
                            "recommendations": [
                                "Block this IP address",
                                "Monitor for related activity",
                                "Investigate abuse reports"
                            ]
                        })
                
                # Total reports
                if "totalReports" in data:
                    results["security_indicators"]["total_reports"] = data["totalReports"]
                
                # Country
                if "countryCode" in data:
                    results["security_indicators"]["abuse_country"] = data["countryCode"]
                
                # Usage type
                if "usageType" in data:
                    results["security_indicators"]["usage_type"] = data["usageType"]
    except Exception as e:
        print(f"Error during AbuseIPDB analysis: {str(e)}")
    
    # Shodan Analysis
    print("\n=== Shodan Analysis ===")
    try:
        shodan = ShodanAPI(os.getenv('SHODAN_API_KEY'))
        shodan_response = shodan.get_ip_info(ip)
        results["threat_intelligence"]["shodan"] = shodan_response
        
        if shodan_response:
            # Extract relevant information
            if "data" in shodan_response:
                for item in shodan_response["data"]:
                    # Ports and services
                    if "port" in item:
                        port = item["port"]
                        if "ports" not in results["security_indicators"]:
                            results["security_indicators"]["ports"] = []
                        results["security_indicators"]["ports"].append(port)
                    
                    # Product information
                    if "product" in item:
                        product = item["product"]
                        if "products" not in results["security_indicators"]:
                            results["security_indicators"]["products"] = []
                        results["security_indicators"]["products"].append(product)
                    
                    # Vulnerabilities
                    if "vulns" in item:
                        vulns = item["vulns"]
                        results["threat_indicators"].append({
                            "type": "shodan_vulnerabilities",
                            "severity": "high",
                            "description": f"Found {len(vulns)} potential vulnerabilities",
                            "potential_risks": [
                                "Exploitation attempts",
                                "Service compromise",
                                "Data breach"
                            ],
                            "recommendations": [
                                "Patch vulnerable services",
                                "Review security configuration",
                                "Monitor for exploitation attempts"
                            ]
                        })
            
            # Hostnames
            if "hostnames" in shodan_response:
                results["security_indicators"]["shodan_hostnames"] = shodan_response["hostnames"]
            
            # Organization
            if "org" in shodan_response:
                results["security_indicators"]["organization"] = shodan_response["org"]
            
            # ASN
            if "asn" in shodan_response:
                results["security_indicators"]["shodan_asn"] = shodan_response["asn"]
            
            # Country
            if "country_name" in shodan_response:
                results["security_indicators"]["shodan_country"] = shodan_response["country_name"]
    except Exception as e:
        print(f"Error during Shodan analysis: {str(e)}")
    
    # DNS Analysis
    print("\n=== DNS Records ===")
    try:
        # Reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results["dns_records"]["PTR"] = [hostname]
            print(f"PTR Record: {hostname}")
        except Exception as e:
            print(f"No PTR record found: {str(e)}")
            results["dns_records"]["PTR"] = []
        
        # Check for suspicious characteristics
        if results["dns_records"].get("PTR"):
            hostname = results["dns_records"]["PTR"][0]
            suspicious_patterns = [
                (r'\d+', "Contains numbers"),
                (r'[_-]', "Contains special characters"),
                (r'[A-Z]', "Contains uppercase letters")
            ]
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, hostname):
                    results["threat_indicators"].append({
                        "type": "suspicious_hostname",
                        "severity": "medium",
                        "description": f"Hostname {description}",
                        "potential_risks": [
                            "Malicious infrastructure",
                            "Command and control server",
                            "Phishing infrastructure"
                        ],
                        "recommendations": [
                            "Verify hostname legitimacy",
                            "Monitor for suspicious activity",
                            "Consider blocking this IP"
                        ]
                    })
        
        # Check if IP is in private range
        if ip_obj.is_private:
            results["security_indicators"]["private_ip"] = True
            results["threat_indicators"].append({
                "type": "private_ip",
                "severity": "high",
                "description": "IP address is in private range",
                "potential_risks": [
                    "Internal network exposure",
                    "Potential data leakage",
                    "Unauthorized access"
                ],
                "recommendations": [
                    "Verify this is an expected private IP",
                    "Check network segmentation",
                    "Review access controls"
                ]
            })
        
        # Check if IP is in reserved range
        if ip_obj.is_reserved:
            results["security_indicators"]["reserved_ip"] = True
            results["threat_indicators"].append({
                "type": "reserved_ip",
                "severity": "high",
                "description": "IP address is in reserved range",
                "potential_risks": [
                    "Misconfiguration",
                    "Potential security bypass",
                    "Unauthorized access"
                ],
                "recommendations": [
                    "Verify IP allocation",
                    "Check network configuration",
                    "Review routing tables"
                ]
            })
        
        # Check if IP is in multicast range
        if ip_obj.is_multicast:
            results["security_indicators"]["multicast_ip"] = True
            results["threat_indicators"].append({
                "type": "multicast_ip",
                "severity": "medium",
                "description": "IP address is in multicast range",
                "potential_risks": [
                    "Network flooding",
                    "Service disruption",
                    "Resource exhaustion"
                ],
                "recommendations": [
                    "Verify multicast configuration",
                    "Check network segmentation",
                    "Monitor multicast traffic"
                ]
            })
        
        # Check if IP is in loopback range
        if ip_obj.is_loopback:
            results["security_indicators"]["loopback_ip"] = True
            results["threat_indicators"].append({
                "type": "loopback_ip",
                "severity": "high",
                "description": "IP address is in loopback range",
                "potential_risks": [
                    "Local service exposure",
                    "Potential security bypass",
                    "Unauthorized access"
                ],
                "recommendations": [
                    "Verify this is an expected loopback IP",
                    "Check service configuration",
                    "Review access controls"
                ]
            })
        
    except Exception as e:
        print(f"Error during DNS analysis: {str(e)}")
        print("This could be due to:")
        print("- DNS server issues")
        print("- Network connectivity problems")
        print("- DNS resolution timeout")
    
    return results

def main():
    print("\n=== Security Analysis Tool ===")
    print("What would you like to analyze?")
    print("Examples:")
    print("  - Check the security status of 8.8.8.8")
    print("  - What can you tell me about example.com?")
    print("  - Analyze the security posture of data-gadgets.com")
    print("  - Where is 8.8.8.8 located?")
    print("\nEnter your query (or 'quit' to exit):")
    
    while True:
        user_input = input("> ").strip()
        
        if user_input.lower() == 'quit':
            break
        
        print("\n=== Starting Comprehensive Security Analysis ===")
        print("This analysis will use multiple security tools and sources to provide a complete assessment.")
        
        # Extract IP or domain from the query
        target = None
        if "where is" in user_input.lower():
            # Handle "where is" queries
            target = user_input.lower().split("where is")[-1].strip()
            if target.endswith("located?"):
                target = target[:-8].strip()
        else:
            # Handle other query formats
            words = user_input.split()
            for word in words:
                # Check if the word is an IP address
                try:
                    ipaddress.ip_address(word)
                    target = word
                    break
                except ValueError:
                    continue
        
        if not target:
            print("Could not identify an IP address or domain in your query.")
            continue
        
        # Phase 1: Threat Intelligence Analysis
        print("\n=== Phase 1: Threat Intelligence Analysis ===")
        print("Analyzing using VirusTotal, AbuseIPDB, Shodan, and Geolocation...")
        
        # Initialize results dictionary
        results = {}
        
        # Phase 2: Additional Tool Analysis
        print("\n=== Phase 2: Additional Tool Analysis (CybertoolsAgent) ===")
        try:
            # Check if input is an IP address
            try:
                ip_obj = ipaddress.ip_address(target)
                analysis_results = analyze_ip(str(ip_obj))
                
                print("\n=== IP Information ===")
                print(f"IP: {analysis_results['ip']}")
                print(f"Type: {analysis_results.get('ip_type', 'Unknown')}")
                
                if analysis_results.get("geolocation"):
                    print("\n=== Geolocation Information ===")
                    geo = analysis_results["geolocation"]
                    print(f"Location: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}")
                    print(f"Coordinates: {geo.get('latitude', 'Unknown')}, {geo.get('longitude', 'Unknown')}")
                    print(f"Timezone: {geo.get('timezone', 'Unknown')}")
                    print(f"ISP: {geo.get('isp', 'Unknown')}")
                    print(f"ASN: {geo.get('asn', 'Unknown')}")
                
                if analysis_results.get("security_indicators"):
                    print("\n=== Security Indicators ===")
                    for key, value in analysis_results["security_indicators"].items():
                        if isinstance(value, list):
                            print(f"- {key.replace('_', ' ').title()}: {', '.join(map(str, value))}")
                        else:
                            print(f"- {key.replace('_', ' ').title()}: {value}")
                
                if analysis_results.get("threat_indicators"):
                    print("\n⚠️ THREAT INDICATORS:")
                    for indicator in analysis_results["threat_indicators"]:
                        print(f"\n🔴 {indicator['type'].replace('_', ' ').title()} (Severity: {indicator['severity'].upper()})")
                        print(f"   Description: {indicator['description']}")
                        print("   Potential Risks:")
                        for risk in indicator['potential_risks']:
                            print(f"   - {risk}")
                        print("   Recommendations:")
                        for rec in indicator['recommendations']:
                            print(f"   - {rec}")
                
                if analysis_results.get("dns_records"):
                    print("\n=== DNS Records ===")
                    for record_type, records in analysis_results["dns_records"].items():
                        if records:
                            print(f"{record_type} Records: {', '.join(records)}")
                
            except ValueError:
                # Not an IP address, try domain analysis
                domain_match = re.search(r'([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+)[?.,!;:]*', user_input)
                if domain_match:
                    domain = domain_match.group(1)
                    domain_results = analyze_domain(domain)
                    
                    print("\n=== Domain Information ===")
                    print(f"Domain: {domain}")
                    print(f"Age: {domain_results.get('age', 'Unknown')}")
                    print(f"Is New Domain: {domain_results.get('is_new', False)}")
                    
                    if domain_results.get("dns_records"):
                        print("\n=== DNS Records ===")
                        for record_type, records in domain_results["dns_records"].items():
                            if records:
                                print(f"{record_type} Records: {', '.join(records)}")
                    
                    if domain_results.get("whois_info"):
                        print("\n=== WHOIS Information ===")
                        whois_info = domain_results["whois_info"]
                        for key, value in whois_info.items():
                            if value:
                                print(f"{key.replace('_', ' ').title()}: {value}")
                    
                    # AI Analysis Summary
                    print("\n=== AI Analysis Summary ===")
                    print(f"Based on the analysis of {user_input}, here are the key findings:")
                    
                    ai_summary = generate_ai_summary(
                        domain,
                        domain_results.get("dns_records", {}),
                        domain_results.get("whois_info", {}),
                        domain_results.get("age", "Unknown")
                    )
                    
                    print("\nDomain Analysis:")
                    print(f"Domain: {ai_summary['domain']}")
                    
                    if ai_summary["infrastructure"]:
                        print("\nInfrastructure:")
                        for key, value in ai_summary["infrastructure"].items():
                            print(f"- {key.replace('_', ' ').title()}: {', '.join(value) if isinstance(value, list) else value}")
                    
                    if ai_summary["security_indicators"]:
                        print("\nSecurity Indicators:")
                        for key, value in ai_summary["security_indicators"].items():
                            print(f"- {key.replace('_', ' ').title()}: {value}")
                    
                    if ai_summary["threat_indicators"]:
                        print("\n⚠️ THREAT INDICATORS:")
                        for indicator in ai_summary["threat_indicators"]:
                            print(f"\n🔴 {indicator['type'].replace('_', ' ').title()} (Severity: {indicator['severity'].upper()})")
                            print(f"   Description: {indicator['description']}")
                            print("   Potential Risks:")
                            for risk in indicator['potential_risks']:
                                print(f"   - {risk}")
                    
                    if ai_summary["security_assessment"]:
                        print("\nSecurity Assessment:")
                        print(f"- Overall Score: {ai_summary['security_assessment']['score']}/5")
                        print(f"- Security Level: {ai_summary['security_assessment']['level']}")
                        if ai_summary["security_assessment"]["factors"]:
                            print("- Contributing Factors:")
                            for factor in ai_summary["security_assessment"]["factors"]:
                                print(f"  * {factor}")
                    
                    if ai_summary["recommendations"]:
                        print("\nRecommendations:")
                        for rec in ai_summary["recommendations"]:
                            print(f"- {rec}")
                else:
                    print("No domain or IP analysis available.")
            
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
        
        print("\n=== Analysis Complete ===")
        print("The analysis has been completed using multiple security tools and sources.")
        print("Review both phases above for a comprehensive security assessment.")
        
        print("\n=== Security Analysis Tool ===")
        print("What would you like to analyze?")
        print("Examples:")
        print("  - Check the security status of 8.8.8.8")
        print("  - What can you tell me about example.com?")
        print("  - Analyze the security posture of data-gadgets.com")
        print("  - Where is 8.8.8.8 located?")
        print("\nEnter your query (or 'quit' to exit):")

if __name__ == "__main__":
    main() 