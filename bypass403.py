#!/usr/bin/env python3
"""
Secret Snatcher - Web Security Scanner for Exposed Sensitive Files
Author: Security Tool
Disclaimer: Use only for authorized testing and educational purposes
Version: 2.0 - Fixed false positive detection
"""

import requests
import os
import sys
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time
import json
import re

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    YELLOW = '\033[93m'

# Common sensitive files and directories to check
SENSITIVE_PATHS = [
    # Configuration files
    ".env", ".env.local", ".env.production", ".env.backup",
    "config.php", "config.ini", "config.json", "config.yml",
    "wp-config.php", "wp-config.bak", "settings.py",
    "application.properties", "application.yml", "appsettings.json",
    
    # Database files
    ".db", ".sqlite", ".sqlite3", ".db3", ".mdb",
    "database.sql", "backup.sql", "dump.sql",
    
    # Backup files
    ".bak", ".backup", ".old", ".orig", ".swp", ".swo",
    "backup.zip", "backup.tar", "backup.tar.gz", "backup.7z",
    
    # Log files
    "error.log", "access.log", "debug.log", "app.log",
    "laravel.log", "production.log",
    
    # Sensitive data files
    "passwords.txt", "users.txt", "credentials.txt",
    "emails.txt", "emails.csv", "users.csv",
    "private.txt", "secret.txt", "keys.txt",
    
    # SSH and certificates
    "id_rsa", "id_dsa", "ssh_key", ".ssh/id_rsa",
    "cert.pem", "key.pem", "private.key", "server.crt",
    
    # Token and API files
    ".token", "api_keys.txt", "apikeys.txt", "secrets.json",
    
    # Git and version control
    ".git/config", ".gitignore", ".git/logs/HEAD",
    ".svn/entries", ".hg/hgrc",
    
    # PHP info and debug
    "phpinfo.php", "info.php", "test.php", "debug.php",
    
    # Administrative interfaces
    "admin/backup.sql", "admin/config.php", "backup/admin.sql",
    
    # Old and temporary files
    "old/", "temp/", "tmp/", "backup/",
    "~/", "~/.bash_history",
    
    # Web server files
    ".htaccess", ".htpasswd", "web.config",
    
    # Sensitive directories
    "backup/", "backups/", "database/", "db/", "sql/",
    "private/", "secure/", "conf/", "config/", "etc/",
]

# Patterns to identify sensitive content in responses
CONTENT_PATTERNS = {
    "Password": re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"]?[\w\-_!@#$%^&*]+',
                          re.IGNORECASE),
    "Email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "API Key": re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*[\'"]?[\w\-]+',
                         re.IGNORECASE),
    "Database Credentials": re.compile(r'(?i)(db[_-]?user|database[_-]?user|db[_-]?pass|mysql|postgresql)\s*[=:]\s*[\'"]?\w+',
                                      re.IGNORECASE),
    "Token": re.compile(r'(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*[\'"]?[\w\-\.]+',
                       re.IGNORECASE),
    "IP Address": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    "JWT Token": re.compile(r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'),
}

class SecretSnatcher:
    def __init__(self, target_url, filename):
        self.target_url = target_url.rstrip('/')
        self.filename = filename
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Connection': 'keep-alive'
        })
        self.results = []
        self.false_positives = []
        
    def print_colored(self, text, color=Colors.WHITE):
        """Print colored text to console"""
        print(f"{color}{text}{Colors.RESET}")
    
    def is_error_page(self, content, url):
        """Check if response is a custom error page, not the actual file"""
        content_lower = content.lower()[:5000]  # Check first 5000 chars only
        filename = url.split('/')[-1].lower()
        
        # Common error indicators
        error_indicators = [
            "page not found",
            "404 error",
            "404 not found",
            "the requested url was not found",
            "sorry, the page you requested could not be found",
            "<title>404",
            "<title>error",
            "does not exist",
            "was not found",
            "can't be found",
            "we couldn't find",
            "not found on this server",
            "http error 404"
        ]
        
        # Check for error indicators
        for indicator in error_indicators:
            if indicator in content_lower:
                # If the requested filename appears in error message, definitely a false positive
                if filename in content_lower and len(filename) > 3:
                    return True
                # Or if the content is clearly HTML with error patterns
                if '<html' in content_lower and indicator in content_lower:
                    return True
                    
        # Check if content is HTML with error status in title
        if '<title>' in content_lower and ('404' in content_lower or 'not found' in content_lower):
            return True
            
        return False
    
    def is_likely_legitimate(self, content, url):
        """Check if the content appears to be the actual requested file"""
        filename = url.split('/')[-1].lower()
        content_lower = content.lower()[:2000]
        
        # Legitimate indicators for specific file types
        legitimate_indicators = {
            '.env': ['db_', 'database', 'password', 'app_env', 'secret_key', 'api_key'],
            'wp-config.php': ["define('db_name'", "define('db_user'", "table_prefix", "auth_key"],
            'config.php': ['<?php', '$db', 'config', 'database'],
            '.json': ['{', '}', '"key"', '"secret"'],
            '.yml': ['- ', ':', 'database:', 'password:'],
            '.ini': ['=', '[database]', '[production]']
        }
        
        # Check for file-specific legitimate content
        for pattern_file, indicators in legitimate_indicators.items():
            if filename.endswith(pattern_file) or filename == pattern_file:
                for indicator in indicators:
                    if indicator in content_lower:
                        return True
        
        # If content is very short and not HTML, could be legitimate
        if len(content) < 2000 and not re.search(r'<html|<body', content_lower):
            return True
            
        return False
    
    def test_url(self, path):
        """Test a specific URL path for sensitive files"""
        full_url = urljoin(self.target_url, path)
        result = {
            "url": full_url,
            "status": None,
            "size": 0,
            "content_type": None,
            "findings": [],
            "error": None,
            "false_positive": False
        }
        
        try:
            # Don't follow redirects automatically
            response = self.session.get(full_url, timeout=5, allow_redirects=False)
            result["status"] = response.status_code
            result["size"] = len(response.content)
            result["content_type"] = response.headers.get('content-type', 'unknown')
            
            # Check for successful responses
            if response.status_code in [200, 301, 302, 403]:
                
                # For 200 responses, check for false positives
                if result["status"] == 200 and 'text' in result["content_type"]:
                    try:
                        content = response.text
                        
                        # Check if this is likely a false positive (error page)
                        if self.is_error_page(content, full_url):
                            result["false_positive"] = True
                            result["error"] = "False positive - Custom error page detected"
                            self.print_colored(f"[!] False positive: {full_url} (returns 200 error page)", Colors.YELLOW)
                            return result
                        
                        # Check if legitimate and analyze content
                        if self.is_likely_legitimate(content, full_url):
                            for pattern_name, pattern in CONTENT_PATTERNS.items():
                                matches = pattern.findall(content)
                                if matches:
                                    unique_matches = list(set(matches))[:5]
                                    for match in unique_matches:
                                        result["findings"].append({
                                            "type": pattern_name,
                                            "value": match[:100]
                                        })
                            
                            self.print_colored(f"[+] Found legitimate file: {full_url} (Status: {response.status_code})", Colors.RED)
                        else:
                            # Content doesn't match expected patterns but isn't clearly an error page
                            result["error"] = "Potential false positive - Unusual content"
                            self.print_colored(f"[?] Suspicious: {full_url} (unusual content)", Colors.YELLOW)
                            
                    except Exception as e:
                        result["error"] = f"Content analysis failed: {str(e)}"
                
                elif result["status"] in [301, 302, 403]:
                    self.print_colored(f"[+] Access restricted/redirect: {full_url} (Status: {response.status_code})", Colors.WHITE)
                
        except requests.exceptions.Timeout:
            result["error"] = "Timeout"
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection Error"
        except Exception as e:
            result["error"] = str(e)
            
        return result
    
    def scan(self):
        """Main scanning function"""
        self.print_colored(f"\n{Colors.BOLD}Secret Snatcher v2.0 - Starting Scan{Colors.RESET}", Colors.RED)
        self.print_colored(f"Target: {self.target_url}", Colors.WHITE)
        self.print_colored(f"Checking {len(SENSITIVE_PATHS)} potential sensitive paths...\n", Colors.WHITE)
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_path = {executor.submit(self.test_url, path): path for path in SENSITIVE_PATHS}
            
            for future in as_completed(future_to_path):
                result = future.result()
                # Only add to results if it's a legitimate finding or redirect/403
                if result["status"] in [200, 301, 302, 403] and not result["false_positive"]:
                    if result["status"] == 200 and not result["error"]:
                        self.results.append(result)
                    elif result["status"] in [301, 302, 403]:
                        self.results.append(result)
                elif result["false_positive"]:
                    # Track false positives separately if needed
                    pass
    
    def save_results(self):
        """Save scan results to text file"""
        try:
            with open(self.filename, 'w', encoding='utf-8') as f:
                # Write header
                f.write("=" * 80 + "\n")
                f.write("SECRET SNATCHER v2.0 - SCAN REPORT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Target URL: {self.target_url}\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Paths Checked: {len(SENSITIVE_PATHS)}\n")
                f.write(f"Legitimate Vulnerabilities Found: {len(self.results)}\n")
                f.write("=" * 80 + "\n\n")
                
                if not self.results:
                    f.write("No confirmed exposed sensitive files found.\n")
                    f.write("Note: Some paths may return HTTP 200 but serve custom error pages.\n")
                else:
                    # Separate findings by type
                    confirmed = [r for r in self.results if r["status"] == 200 and r["findings"]]
                    restricted = [r for r in self.results if r["status"] in [301, 302, 403]]
                    
                    if confirmed:
                        f.write("CONFIRMED EXPOSURES (with sensitive data):\n")
                        f.write("-" * 40 + "\n")
                        for idx, result in enumerate(confirmed, 1):
                            f.write(f"\n[{idx}] {result['url']}\n")
                            f.write(f"Status Code: {result['status']}\n")
                            f.write(f"Content Size: {result['size']} bytes\n")
                            f.write(f"Content Type: {result['content_type']}\n")
                            
                            if result['findings']:
                                f.write("\nSensitive Content Found:\n")
                                for finding in result['findings']:
                                    f.write(f"  - {finding['type']}: {finding['value']}\n")
                            
                            if result['error']:
                                f.write(f"Note: {result['error']}\n")
                            
                            f.write("\n")
                    
                    if restricted:
                        f.write("\nACCESS RESTRICTED OR REDIRECTED:\n")
                        f.write("-" * 40 + "\n")
                        for idx, result in enumerate(restricted, 1):
                            f.write(f"\n[{idx}] {result['url']}\n")
                            f.write(f"Status Code: {result['status']}\n")
                            f.write(f"Content Type: {result['content_type']}\n\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("LEGEND:\n")
                f.write("- Confirmed Exposures: Files that return 200 with actual content\n")
                f.write("- Access Restricted: Returns 301/302/403 (may still be interesting)\n")
                f.write("- False Positives: Files returning 200 but serving error pages\n")
                f.write("=" * 80 + "\n")
                f.write("DISCLAIMER: This tool is for educational and authorized testing only.\n")
                f.write("Unauthorized scanning of websites may be illegal in your jurisdiction.\n")
                f.write("=" * 80 + "\n")
            
            self.print_colored(f"\n[✓] Results saved to: {self.filename}", Colors.RED)
            return True
        except Exception as e:
            self.print_colored(f"\n[✗] Error saving results: {str(e)}", Colors.RED)
            return False
    
    def print_summary(self):
        """Print scan summary to console"""
        self.print_colored(f"\n{Colors.BOLD}SCAN SUMMARY{Colors.RESET}", Colors.RED)
        self.print_colored("=" * 50, Colors.WHITE)
        
        confirmed = [r for r in self.results if r["status"] == 200 and r["findings"]]
        restricted = [r for r in self.results if r["status"] in [301, 302, 403]]
        
        self.print_colored(f"Confirmed exposures with sensitive data: {len(confirmed)}", Colors.WHITE)
        self.print_colored(f"Access restricted/redirected files: {len(restricted)}", Colors.WHITE)
        self.print_colored(f"Total interesting findings: {len(self.results)}", Colors.WHITE)
        
        if confirmed:
            self.print_colored("\nConfirmed exposed files (verify manually):", Colors.RED)
            for result in confirmed[:5]:  # Show first 5 in console
                self.print_colored(f"  - {result['url']}", Colors.WHITE)
            if len(confirmed) > 5:
                self.print_colored(f"  ... and {len(confirmed) - 5} more confirmed exposures", Colors.WHITE)
        
        if restricted and not confirmed:
            self.print_colored("\nNo confirmed exposures found, but these files exist:", Colors.YELLOW)
            for result in restricted[:5]:
                self.print_colored(f"  - {result['url']} (Status: {result['status']})", Colors.WHITE)

def validate_url(url):
    """Validate and normalize URL"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def main():
    """Main function"""
    print(f"{Colors.BOLD}{Colors.RED}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                SECRET SNATCHER v2.0                      ║")
    print("║         Exposed Sensitive Files Scanner                  ║")
    print("║      Now with False Positive Detection!                  ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    # Disclaimer
    print(f"{Colors.RED}{Colors.BOLD}DISCLAIMER:{Colors.RESET}{Colors.WHITE}")
    print("This tool is for educational purposes and authorized security testing only.")
    print("Only scan websites you own or have explicit permission to test.")
    print("Unauthorized scanning may violate laws and regulations.\n")
    
    # Authorization confirmation
    print(f"{Colors.YELLOW}⚠️  LEGAL REQUIREMENT:{Colors.RESET}")
    authorized = input(f"{Colors.WHITE}Do you have WRITTEN permission to test this target? (yes/no): {Colors.RESET}")
    if authorized.lower() not in ['yes', 'y']:
        print(f"{Colors.RED}Exiting. Never scan without permission.{Colors.RESET}")
        sys.exit(0)
    
    # Get target URL
    while True:
        target_url = input(f"{Colors.WHITE}Enter target URL (example: https://example.com): {Colors.RESET}").strip()
        if target_url:
            target_url = validate_url(target_url)
            break
        print(f"{Colors.RED}Please enter a valid URL.{Colors.RESET}")
    
    # Get output filename
    while True:
        filename = input(f"{Colors.WHITE}Enter filename to save results (example: results.txt): {Colors.RESET}").strip()
        if filename:
            if not filename.endswith('.txt'):
                filename += '.txt'
            break
        print(f"{Colors.RED}Please enter a filename.{Colors.RESET}")
    
    try:
        # Initialize and run scanner
        scanner = SecretSnatcher(target_url, filename)
        start_time = time.time()
        scanner.scan()
        elapsed_time = time.time() - start_time
        
        # Save results and show summary
        scanner.save_results()
        scanner.print_summary()
        
        print(f"{Colors.WHITE}\nScan completed in {elapsed_time:.2f} seconds.{Colors.RESET}")
        print(f"{Colors.YELLOW}Note: Always manually verify findings - false positives are possible!{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}\n[!] Scan interrupted by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}\n[!] An error occurred: {str(e)}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
