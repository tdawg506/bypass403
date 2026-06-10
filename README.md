# 403 Bypass Tool

A comprehensive security tool to test various techniques for bypassing 403 forbidden restrictions on web servers.

<br>

## Features

* Header injection bypasses (X-Forwarded-For, X-Originating-IP, etc)
* Path manipulation techniques (directory traversal,encoding tricks)
* HTTP method fuzzing (POST, PUT, DELETE, PATCH, OPTIONS, etc.)
* URL encoding bypasses (double encoding, unicode, UTF-8
* Case sensitivity testing
* Query parameter injection
* Random User-Agent rotation to bypass firewalls
* Multi-threaded scanning for speed

<br>

## Installation

Clone the repository:
```bash
git clone https://github.com/tdawg506/bypass403.git
cd bypass403
```
Install the required dependencies:
```bash
pip3 install -r requirements.txt 
```
<br>

## Usage

Basic scan:
```bash
python3 bypass403.py https://example.com/admin
```
Scan with custom threads and verbose output:
```bash
python3 bypass403.py https://example.com/secret --threads 20 --verbose
```
Disable random User-Agent:
```bash
python3 bypass403.py https://example.com/api --no-random-ua
```
Show all results including non-bypass statuses:
```bash
python3 bypass403.py https://example.com/private --show-all
```
<br>

### Disclaimer

This tool is for educational and authorized testing purposes only. Only use on systems you own or have permission to test.