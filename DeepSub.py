#!/usr/bin/env python3

import subprocess
import requests
import json
import shutil
import os
import time
import re
import threading
import argparse
import dns.resolver
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from colorama import Fore, Style, init
from tqdm import tqdm
import random
import ipaddress

# Initialize colorama for cross-platform colored output
init()

class DeepSub:
    def __init__(self):
        # ===========================
        # INSERT YOUR API KEYS HERE
        # ===========================
        self.SHODAN_API_KEY = "your-key" 
        self.VIRUSTOTAL_API_KEY = "your-key"
        self.DNSDUMPSTER_API_KEY = "your-key"
        self.SECURITYTRAILS_API_KEY = "your-key"
        self.URLSCAN_API_KEY = "your-key"
        # ===========================
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        self.results = {}
        self.alive_subs = set()
        self.dead_subs = set()
        self.resolved_ips = {}  # Store subdomain -> IP mappings

    def print_banner(self):

        banner = fr'''
        {Fore.CYAN}
    ____                 _____       __        
   / __ \___  ___  ____ / ___/__  __/ /_  _____
  / / / / _ \/ _ \/ __ \\__ \/ / / / __ \/ ___/
 / /_/ /  __/  __/ /_/ /__/ / /_/ / /_/ (__  ) 
/_____/\___/\___/ .___/____/\__,_/_.___/____/  
               /_/                 
     Advanced Subdomain Enumeration Tool
        {Style.RESET_ALL}
        '''
        
        print(banner)

    def log_info(self, message, tool=None):
        if tool:
            print(f"{Fore.BLUE}[{tool}]{Style.RESET_ALL} {message}")
        else:
            print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

    def log_warning(self, message, tool=None):
        if tool:
            print(f"{Fore.YELLOW}[{tool}]{Style.RESET_ALL} {message}")
        else:
            print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

    def log_error(self, message, tool=None):
        if tool:
            print(f"{Fore.RED}[{tool}]{Style.RESET_ALL} {message}")
        else:
            print(f"{Fore.RED}{message}{Style.RESET_ALL}")

    def get_random_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }

    def run_tool(self, command):
        try:
            output = subprocess.check_output(
                command, 
                shell=True, 
                stderr=subprocess.DEVNULL
            )
            return output.decode(errors='ignore').splitlines()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return []

    def filter_subdomains(self, subdomains, domain):
        filtered = set()
        for sub in subdomains:
            sub = sub.strip().lower()
            if sub and sub.endswith(domain) and not sub.startswith('*'):
                # Remove wildcards and clean the subdomain
                sub = re.sub(r'^\*\.', '', sub)
                if sub and '.' in sub:
                    filtered.add(sub)
        return filtered

    def validate_domain(self, domain):
        """Validate domain format"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain)) and len(domain) <= 253
		
	
    def extract_amass_subdomains(self, lines, domain):
		subdomains = set()
		for line in lines:
			line = line.strip()
			if not line:
				continue
			first_part = line.split()[0]
			if first_part.endswith(domain):
				subdomains.add(first_part)
		return subdomains
		
	
    def resolve_subdomain_ip(self, subdomain, timeout=5):
        """Resolve a single subdomain to its IP address(es), excluding localhost"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=timeout)
            ips = []
            for answer in answers:
                ip = str(answer)
                if not ipaddress.ip_address(ip).is_loopback:
                    ips.append(ip)
            if ips:
                return subdomain, ips, True
            else:
                return subdomain, [], False
        except:
            return subdomain, [], False

    def resolve_subdomains_bulk(self, subdomains, max_workers=50):
        """Resolve multiple subdomains to their IP addresses"""
        self.log_info("🔍 Resolving subdomain IP addresses...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sub = {
                executor.submit(self.resolve_subdomain_ip, sub): sub 
                for sub in subdomains
            }
            
            with tqdm(total=len(subdomains), desc="Resolving IPs") as pbar:
                for future in as_completed(future_to_sub):
                    subdomain = future_to_sub[future]
                    try:
                        sub, ips, success = future.result()
                        if success and ips:
                            self.resolved_ips[sub] = ips
                    except Exception as e:
                        pass  # Skip failed resolutions
                    pbar.update(1)

    def check_subdomain_alive(self, subdomain, timeout=5):
        """Check if subdomain is alive using multiple methods"""
        try:
            # Method 1: DNS resolution
            dns.resolver.resolve(subdomain, 'A')
            
            # Method 2: HTTP/HTTPS check
            for protocol in ['https', 'http']:
                try:
                    response = requests.head(
                        f"{protocol}://{subdomain}",
                        timeout=timeout,
                        headers=self.get_random_headers(),
                        allow_redirects=True
                    )
                    if response.status_code < 400:
                        return True, f"{protocol}://{subdomain}", response.status_code
                except:
                    continue
            return True, None, None
        except:
            return False, None, None

    def probe_subdomains(self, subdomains, max_workers=50):
        """Probe subdomains to check if they're alive"""
        self.log_info("🔍 Probing subdomains for alive hosts...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sub = {
                executor.submit(self.check_subdomain_alive, sub): sub 
                for sub in subdomains
            }
            
            with tqdm(total=len(subdomains), desc="Probing") as pbar:
                for future in as_completed(future_to_sub):
                    subdomain = future_to_sub[future]
                    try:
                        is_alive, url, status_code = future.result()
                        if is_alive:
                            self.alive_subs.add(subdomain)
                        else:
                            self.dead_subs.add(subdomain)
                    except Exception as e:
                        self.dead_subs.add(subdomain)
                    pbar.update(1)
    
    def get_subfinder(self, domain):
        self.log_info("Searching...", "subfinder")
        if not shutil.which("subfinder"):
            self.log_warning("Not installed or not in PATH", "subfinder")
            return set()
        
        results = self.run_tool(f"subfinder -d {domain} -silent -timeout 10")
        subs = self.filter_subdomains(set(results), domain)
        self.results['subfinder'] = len(subs)
        self.log_info(f"Found {len(subs)} subdomains", "subfinder")
        return subs

    def get_amass(self, domain):
        self.log_info("Searching...", "amass")
        if not shutil.which("amass"):
            self.log_warning("Not installed or not in PATH", "amass")
            return set()
        results = self.run_tool(f"amass enum -d {domain} -passive -timeout 5")
        subs = self.extract_amass_subdomains(results, domain)
        self.results['amass'] = len(subs)
        self.log_info(f"Found {len(subs)} subdomains", "amass")
        return subs
    
    def get_assetfinder(self, domain):
        self.log_info("Searching...", "assetfinder")
        if not shutil.which("assetfinder"):
            self.log_warning("Not installed or not in PATH", "assetfinder")
            return set()
        
        results = self.run_tool(f"assetfinder --subs-only {domain}")
        subs = self.filter_subdomains(set(results), domain)
        self.results['assetfinder'] = len(subs)
        self.log_info(f"Found {len(subs)} subdomains", "assetfinder")
        return subs

    def get_findomain(self, domain):
        self.log_info("Searching...", "findomain")
        if not shutil.which("findomain"):
            self.log_warning("Not installed or not in PATH", "findomain")
            return set()
        
        results = self.run_tool(f"findomain -t {domain} -q")
        subs = self.filter_subdomains(set(results), domain)
        self.results['findomain'] = len(subs)
        self.log_info(f"Found {len(subs)} subdomains", "findomain")
        return subs

    def get_knockpy(self, domain):
        self.log_info("Searching...", "knockpy")
        if not shutil.which("knockpy"):
            self.log_warning("Not installed or not in PATH", "knockpy")
            return set()
        
        try:
            results = self.run_tool(f"knockpy -d {domain} --recon --bruteforce")
            matches = re.findall(r'36m(.*?)\\', str(results))
            cleaned_set = {
                s.strip().lower()
                for s in matches
                if not s.strip().startswith("*")
            }
                    
            subs = self.filter_subdomains(cleaned_set, domain)
                
            self.results['knockpy'] = len(subs)
            self.log_info(f"Found {len(subs)} subdomains", "knockpy")
            return subs
        except Exception as e:
            self.log_error(f"Error: {str(e)}", "knockpy")
            return set()

    def get_threatcrowd(self, domain):
        self.log_info("Searching...", "threatcrowd")
        url = f"http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        
        try:
            response = requests.get(url, headers=self.get_random_headers(), timeout=10)
            response.raise_for_status()
            data = response.json()
            subs = self.filter_subdomains(set(data.get("subdomains", [])), domain)
            self.results['threatcrowd'] = len(subs)
            self.log_info(f"Found {len(subs)} subdomains", "threatcrowd")
            return subs
        except Exception as e:
            self.log_error(f"API error: {str(e)}", "threatcrowd")
            return set()

    def get_virustotal(self, domain):
        self.log_info("Searching...", "virustotal")
        if not self.VIRUSTOTAL_API_KEY or self.VIRUSTOTAL_API_KEY == "REDACTED":
            self.log_warning("API key not configured", "virustotal")
            return set()

        headers = {
            "accept": "application/json",
            "x-apikey": self.VIRUSTOTAL_API_KEY
        }
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json().get("data", [])
            subs = {element["id"] for element in data}
            subs = self.filter_subdomains(subs, domain)
            self.results['virustotal'] = len(subs)
            self.log_info(f"Found {len(subs)} subdomains", "virustotal")
            return subs
        except Exception as e:
            self.log_error(f"API error: {str(e)}", "virustotal")
            return set()

    def get_shodan(self, domain):
        self.log_info("Searching...", "shodan")
        if not self.SHODAN_API_KEY or self.SHODAN_API_KEY == "REDACTED":
            self.log_warning("API key not configured", "shodan")
            return set()

        url = f"https://api.shodan.io/dns/domain/{domain}?key={self.SHODAN_API_KEY}"
        
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()
            subs = set()
            for entry in data.get('subdomains', []):
                subs.add(f"{entry}.{domain}")
            subs = self.filter_subdomains(subs, domain)
            self.results['shodan'] = len(subs)
            self.log_info(f"Found {len(subs)} subdomains", "shodan")
            return subs
        except Exception as e:
            self.log_error(f"API error: {str(e)}", "shodan")
            return set()

    def get_crtsh(self, domain):
        self.log_info("Searching...", "crt.sh")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        subs = set()
        
        try:
            response = requests.get(url, headers=self.get_random_headers(), timeout=15)
            response.raise_for_status()
            
            for entry in response.json():
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    if sub.strip().endswith(domain):
                        subs.add(sub.strip())
            
            subs = self.filter_subdomains(subs, domain)
            self.results['crt.sh'] = len(subs)
            self.log_info(f"Found {len(subs)} subdomains", "crt.sh")
            return subs
        except Exception as e:
            self.log_error(f"API error: {str(e)}", "crt.sh")
            return set()

    def get_hackertarget(self, domain):
        self.log_info("Searching...", "hackertarget")
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        
        try:
            response = requests.get(url, headers=self.get_random_headers(), timeout=10)
            response.raise_for_status()
            
            subs = set()
            for line in response.text.splitlines():
                if ',' in line:
                    subdomain = line.split(',')[0].strip()
                    if subdomain.endswith(domain):
                        subs.add(subdomain)
                        
            subs = self.filter_subdomains(subs, domain)
            self.results['hackertarget'] = len(subs)
            self.log_info(f"Found {len(subs)} subdomains", "hackertarget")
            return subs
        except Exception as e:
            self.log_error(f"API error: {str(e)}", "hackertarget")
            return set()

    def get_anubis(self, domain):
        self.log_info("Searching...", "anubis")
        if not shutil.which("anubis"):
            self.log_warning("Not installed or not in PATH", "anubis")
            return set()
        
        results = self.run_tool(f"anubis -t {domain}")
        matches = re.findall(r'92m(.*?)\\', str(results))
        cleaned_set = {
            s.strip().lower()
            for s in matches
            if not s.strip().startswith("*")
        }
                
        subs = self.filter_subdomains(cleaned_set, domain)
        self.results['anubis'] = len(subs)
        self.log_info(f"Found {len(subs)} subdomains", "anubis")
        return subs
        
  
    def get_dnsdumpster(self, domain):
        self.log_info("Searching...", "dnsdumpster")        
        headers = {"X-API-Key": self.DNSDUMPSTER_API_KEY}
        try:
            res = requests.get(f"https://api.dnsdumpster.com/domain/{domain}", headers=headers)
            data = res.json()
            a_records = data.get("a", [])
            subs = {entry["host"] for entry in a_records if "host" in entry}
            subs = self.filter_subdomains(subs, domain)
            self.results['dnsdumpster'] = len(subs)
            self.log_info(f"Found {len(subs)} subdomains", "dnsdumpster")
            return subs
        except:
            return set()

    def get_securitytrails(self, domain):
        self.log_info("Searching...", "securitytrails")        
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?apikey={self.SECURITYTRAILS_API_KEY}"
        headers = {"accept": "application/json"}
        try:
            response = requests.get(url, headers=headers)
            data = response.json()
            subs = {f"{sub}.{domain}" for sub in data.get("subdomains", [])}
            subs = self.filter_subdomains(subs, domain)
            self.results['securitytrails'] = len(subs)
            self.log_info(f"Found {len(subs)} subdomains", "securitytrails")
            return subs
        except:
            return set()

    def get_urlscan(self, domain):
        self.log_info("Searching...", "urlscan.io")        
        headers = {'API-Key': self.URLSCAN_API_KEY, 'Content-Type': 'application/json'}
        data = {"url": domain, "visibility": "private"}
        try:
            res = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
            result_url = res.json().get("api")
            time.sleep(10)
            if result_url:
                final_res = requests.get(result_url)
                js = final_res.json()
                subs = {entry for entry in js.get("lists", {}).get("domains", []) if entry.endswith(domain)}
                self.results['urlscan.io'] = len(subs)
                self.log_info(f"Found {len(subs)} subdomains", "urlscan.io")
                return subs
        except:
            return set()
        return set()

    def get_sublist3r(self, domain):
        self.log_info("Searching...", "sublist3r")
        if not shutil.which("sublist3r"):
            self.log_warning("Not installed or not in PATH", "sublist3r")
            return set()
        
        results = self.run_tool(f"sublist3r -d {domain}")
        
        matches = re.findall(r'92m(.*?)\\', str(results))
        cleaned_set = {
            s.strip().lower()
            for s in matches
            if not s.strip().startswith("*")
        }
                    
        subs = self.filter_subdomains(cleaned_set, domain)
        
        self.results['sublist3r'] = len(subs)
        self.log_info(f"Found {len(subs)} subdomains", "sublist3r")
        return subs
        

    def save_results(self, domain, all_subs, output_format='txt', include_ips=False, probe=False):
        """Save results in different formats"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_filename = f"{domain}_{timestamp}"
        
        if output_format == 'txt':
            filename = f"{base_filename}.txt"
            with open(filename, 'w') as f:
                for sub in sorted(all_subs):
                    if include_ips and sub in self.resolved_ips:
                        ips = ', '.join(self.resolved_ips[sub])
                        f.write(f"{sub} -> {ips}\n")
                    else:
                        f.write(f"{sub}\n")
        
        elif output_format == 'json':
            filename = f"{base_filename}.json"
            data = {
                'domain': domain,
                'timestamp': timestamp,
                'total_subdomains': len(all_subs),
                'alive_subdomains': len(self.alive_subs),
                'resolved_subdomains': len(self.resolved_ips),
                'tool_results': self.results,
                'subdomains': sorted(list(all_subs)),
                'alive': sorted(list(self.alive_subs)),
                'dead': sorted(list(self.dead_subs)),
                'resolved_ips': {k: v for k, v in sorted(self.resolved_ips.items())} if include_ips else {}
            }
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        
        elif output_format == 'csv':
            filename = f"{base_filename}.csv"
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                if include_ips and probe:
                    writer.writerow(['Subdomain', 'Status', 'IP_Addresses'])
                    for sub in sorted(all_subs):
                        status = 'Alive' if sub in self.alive_subs else 'Unknown'
                        ips = ' | '.join(self.resolved_ips.get(sub, [])) if sub in self.resolved_ips else 'N/A'
                        writer.writerow([sub, status, ips])
                if include_ips and not probe:
                    writer.writerow(['Subdomain', 'IP_Addresses'])
                    for sub in sorted(all_subs):
                        ips = ' | '.join(self.resolved_ips.get(sub, [])) if sub in self.resolved_ips else 'N/A'
                        writer.writerow([sub, ips])
                elif probe and not include_ips:
                    writer.writerow(['Subdomain', 'Status'])
                    for sub in sorted(all_subs):
                        status = 'Alive' if sub in self.alive_subs else 'Unknown'
                        writer.writerow([sub, status])
                else:
                    writer.writerow(['Subdomain'])
                    for sub in sorted(all_subs):
                        writer.writerow([sub])
        
        self.log_info(f"Results saved to {filename}")
        return filename

    def print_summary(self, all_subs):
        """Print detailed summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}ENUMERATION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Tool Results:{Style.RESET_ALL}")
        for tool, count in self.results.items():
            print(f"  {tool}: {count} subdomains")
        
        print(f"\n{Fore.YELLOW}Final Statistics:{Style.RESET_ALL}")
        print(f"  Total unique subdomains: {Fore.GREEN}{len(all_subs)}{Style.RESET_ALL}")
        if self.alive_subs:
            print(f"  Alive subdomains: {Fore.GREEN}{len(self.alive_subs)}{Style.RESET_ALL}")
            print(f"  Dead/Unknown: {Fore.RED}{len(self.dead_subs)}{Style.RESET_ALL}")
        if self.resolved_ips:
            print(f"  Resolved IPs: {Fore.CYAN}{len(self.resolved_ips)}{Style.RESET_ALL}")

    def run_enumeration(self, domain, tools=None, probe=False, resolve_ips=False, output_format='txt'):
        """Main enumeration function"""
        if not self.validate_domain(domain):
            self.log_error("Invalid domain format")
            return
        
        self.print_banner()
        print(f"{Fore.YELLOW}Target: {Fore.WHITE}{domain}{Style.RESET_ALL}\n")
        
        # Available tools
        available_tools = {
            'subfinder': self.get_subfinder,
            'amass': self.get_amass,
            'assetfinder': self.get_assetfinder,
            'findomain': self.get_findomain,
            'knockpy': self.get_knockpy,
            'threatcrowd': self.get_threatcrowd,
            'virustotal': self.get_virustotal,
            'shodan': self.get_shodan,
            'crt.sh': self.get_crtsh,
            'sublist3r': self.get_sublist3r,
            'hackertarget': self.get_hackertarget,
            'urlscan.io': self.get_urlscan,
            'securitytrails': self.get_securitytrails,
            'dnsdumpster': self.get_dnsdumpster,
            'anubis': self.get_anubis
        }
    
        # Select tools to run
        if tools:
            selected_tools = {k: v for k, v in available_tools.items() if k in tools}
        else:
            selected_tools = available_tools
        
        all_subs = set()
        
        # Run enumeration tools
        for tool_name, tool_func in selected_tools.items():
            try:
                subs = tool_func(domain)
                all_subs.update(subs)
                time.sleep(1)  # Rate limiting
            except Exception as e:
                self.log_error(f"Unexpected error: {str(e)}", tool_name)
        
        # Probe subdomains if requested
        if probe and all_subs:
            self.probe_subdomains(all_subs)
        
        # Resolve IPs if requested
        if resolve_ips and all_subs:
            self.resolve_subdomains_bulk(all_subs)
        
        # Print results
        self.print_summary(all_subs)

        if self.alive_subs:
            print(f"\n{Fore.YELLOW}Alive Hosts:{Style.RESET_ALL}")
            for sub in sorted(self.alive_subs):
                if resolve_ips and sub in self.resolved_ips:
                    ips = ', '.join(self.resolved_ips[sub])
                    print(f"{Fore.GREEN}{sub}{Style.RESET_ALL} -> {Fore.CYAN}{ips}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}{sub}{Style.RESET_ALL}")
        
        if all_subs:
            print(f"\n{Fore.YELLOW}Discovered Subdomains:{Style.RESET_ALL}")
            for sub in sorted(all_subs):
                if resolve_ips and sub in self.resolved_ips:
                    ips = ', '.join(self.resolved_ips[sub])
                    print(f"{sub} -> {Fore.CYAN}{ips}{Style.RESET_ALL}")
                else:
                    print(f"{sub}")
        
        # Save results
        if all_subs:
            self.save_results(domain, all_subs, output_format, resolve_ips, probe)
        
        return all_subs

def main():
    parser = argparse.ArgumentParser(
        description="DeepSub v1.0 - Advanced Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 deepsub.py example.com
  python3 deepsub.py example.com --probe --output json
  python3 deepsub.py example.com --tools subfinder,amass,crt.sh
  python3 deepsub.py example.com --probe --threads 100 --output csv
        """
    )
    
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--tools", "-t", 
                        help="Comma-separated list of tools to use",
                        default=None)
    parser.add_argument("--probe", "-p", 
                        action="store_true",
                        help="Probe subdomains to check if they're alive")
    parser.add_argument("--output", "-o", 
                        choices=['txt', 'json', 'csv'],
                        default='txt',
                        help="Output format (default: txt)")
    parser.add_argument("--threads", 
                        type=int, 
                        default=50,
                        help="Number of threads for probing (default: 50)")
    parser.add_argument("--resolve",
						action="store_true",
                        help="Resolve subdomains")
	
	
	
	                     
    args = parser.parse_args()
    
    # Parse tools if specified
    tools = None
    if args.tools:
        tools = [tool.strip() for tool in args.tools.split(',')]
    
    # Initialize and run DeepSub
    deepsub = DeepSub()
    deepsub.run_enumeration(
        domain=args.domain,
        tools=tools,
        probe=args.probe,
		resolve_ips=args.resolve,
        output_format=args.output
    )

if __name__ == "__main__":
    main()