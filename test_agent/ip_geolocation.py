#!/usr/bin/env python3
"""
IP Geolocation Script

This script allows you to look up geographic information for IP addresses
using the MaxMind GeoIP2 database or a free online API service.
"""

import sys
import argparse
import requests
import json
from urllib.parse import urlparse
import socket
import ipaddress

def is_valid_ip(ip_str):
    """Check if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def get_ip_from_url(url):
    """Extract IP address from a given URL."""
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

def geolocate_ip_ipapi(ip_address):
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
                "timezone": data.get("timezone")
            }
        else:
            return {"error": data.get("message", "Unknown error")}
            
    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse response"}

def geolocate_ip_ipinfo(ip_address):
    """
    Get geolocation data using the free ipinfo.io service.
    
    This service has a limit of 50,000 requests per month for free usage.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        
        if "bogon" in data or "error" in data:
            return {"error": data.get("error", {}).get("message", "Invalid IP address")}
        
        # Parse the location coordinates
        loc = data.get("loc", "").split(",")
        latitude = loc[0] if len(loc) > 0 else None
        longitude = loc[1] if len(loc) > 1 else None
        
        return {
            "ip": ip_address,
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": latitude,
            "longitude": longitude,
            "org": data.get("org"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone")
        }
            
    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse response"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def display_geolocation_data(geo_data):
    """Display geolocation data in a readable format."""
    if "error" in geo_data:
        print(f"Error: {geo_data['error']}")
        return
        
    print("\n==== IP Geolocation Results ====")
    print(f"IP Address: {geo_data.get('ip')}")
    print(f"Country: {geo_data.get('country')} ({geo_data.get('country_code', '')})")
    print(f"Region: {geo_data.get('region')}")
    print(f"City: {geo_data.get('city')}")
    print(f"Location: {geo_data.get('latitude')}, {geo_data.get('longitude')}")
    print(f"ISP/Organization: {geo_data.get('isp', geo_data.get('org', 'N/A'))}")
    print(f"Timezone: {geo_data.get('timezone', 'N/A')}")
    print("==============================\n")

def main():
    parser = argparse.ArgumentParser(description='IP Address Geolocation Tool')
    parser.add_argument('ip_or_url', nargs='?', help='IP address or URL to geolocate')
    parser.add_argument('-s', '--service', choices=['ipapi', 'ipinfo'], default='ipapi',
                        help='Geolocation service to use (default: ipapi)')
    args = parser.parse_args()
    
    # If no IP or URL is provided, use the current IP
    if not args.ip_or_url:
        print("No IP address or URL provided, getting your current IP information...")
        response = requests.get("https://api.ipify.org?format=json")
        ip_address = response.json()["ip"]
    else:
        # Check if the input is a URL or an IP address
        if is_valid_ip(args.ip_or_url):
            ip_address = args.ip_or_url
        else:
            print(f"Input appears to be a domain or URL. Resolving to IP address...")
            ip_address = get_ip_from_url(args.ip_or_url)
            if not ip_address:
                sys.exit(1)
            print(f"Resolved to IP address: {ip_address}")
    
    # Get geolocation data using the selected service
    if args.service == 'ipapi':
        geo_data = geolocate_ip_ipapi(ip_address)
    else:  # ipinfo
        geo_data = geolocate_ip_ipinfo(ip_address)
        
    display_geolocation_data(geo_data)

if __name__ == "__main__":
    main()
