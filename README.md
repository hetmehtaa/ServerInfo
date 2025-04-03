# DomainInfoSec.sh - Domain Security Information Gathering Tool

A comprehensive Bash script designed to gather various cybersecurity-related information about a given domain. It aims for cross-platform compatibility (Linux & macOS) and provides colorized output for better readability.

**Current Location Context:** Ahmedabad, Gujarat, India (as of script generation context - April 3, 2025)

---

> **🚨 LEGAL DISCLAIMER 🚨**
>
> This script is intended for **educational purposes ONLY**.
> Use it solely on systems and networks where you have **explicit, prior, written authorization**.
> Unauthorized scanning or testing of systems is **illegal and unethical**.
> The author assumes **NO liability** for misuse of this script.
> **Use responsibly and legally.**

---

## Features

This script gathers the following information:

* **IP Address & Reverse DNS:** Resolves the domain's primary A record and performs a reverse lookup.
* **Common DNS Records:** Fetches MX, NS, TXT, and SOA records.
* **DNS Security Records:** Checks for SPF (in TXT), DMARC (_dmarc TXT), and DNSKEY (DNSSEC presence).
* **WHOIS Information:** Retrieves registration details for the domain (requires `whois` tool).
* **HTTP/HTTPS Headers:** Fetches headers from both HTTP and HTTPS endpoints.
* **HTTP Security Headers:** Checks for the presence of common security headers like HSTS, CSP, X-Frame-Options, etc., in the HTTPS response.
* **SSL/TLS Certificate Details:** Displays Issuer, Subject, Validity Dates, Serial Number, and Fingerprint for the HTTPS certificate.
* **Network Path (Traceroute):** Shows the network hops to the target domain (requires `traceroute`).
* **Basic Reachability (Ping):** Sends ICMP packets to check if the host is responsive.
* **Port Scan (Optional):** Performs a basic Nmap scan (Top 100 ports) if `nmap` is installed and user confirms. **(Requires explicit permission!)**
* **Subdomain Enumeration (Optional):** Uses `subfinder` or `assetfinder` (if installed) to find subdomains via passive sources, requires user confirmation.

## Prerequisites

### Core Tools

These tools are generally required for the script's main functions.

* **Bash:** v4.0 or higher recommended.
* **Core Network Utilities:** `ping`, `traceroute`
* **DNS Utilities:** `dig`, `host` (Often in packages like `dnsutils`, `bind-utils`)
* **Web Utility:** `curl`
* **Cryptography Utility:** `openssl`
* **WHOIS Utility:** `whois`

**Installation Hints:**

* **Debian/Ubuntu:**
    ```bash
    sudo apt update && sudo apt install -y bash dnsutils curl openssl whois traceroute iputils-ping
    ```
* **Fedora/CentOS/RHEL:**
    ```bash
    sudo dnf install -y bash bind-utils curl openssl whois traceroute iputils
    # Or using yum:
    # sudo yum install -y bash bind-utils curl openssl whois traceroute iputils
    ```
* **macOS (using Homebrew):**
    ```bash
    brew install bash curl openssl whois coreutils # (ping/traceroute usually built-in)
    # Ensure dig/host are available (might be via bind or separate package if not default)
    # brew install bind
    ```

### Optional Tools

These tools enable optional features (Port Scanning, Subdomain Enumeration).

* **Nmap:** For port scanning (`Section 9`).
* **Subfinder OR Assetfinder:** For subdomain enumeration (`Section 10`).
* **timeout:** (Often part of `coreutils` on Linux) Provides better control for the SSL check duration.

**Installation Hints:**

* **Debian/Ubuntu:**
    ```bash
    sudo apt install -y nmap subfinder assetfinder coreutils
    ```
* **Fedora/CentOS/RHEL:**
    ```bash
    sudo dnf install -y nmap subfinder assetfinder coreutils
    # Or using yum:
    # sudo yum install -y nmap subfinder assetfinder coreutils
    ```
* **macOS (using Homebrew):**
    ```bash
    brew install nmap subfinder assetfinder coreutils
    ```

*(Note: Package names might vary slightly between distributions and versions.)*

## Usage

1.  **Clone the repository:**
    ```bash
    git clone <repo_url>
    cd <repo_directory_name>
    ```
    Alternatively, download the `DomainInfoSec.sh` script file directly.

2.  **Make the script executable:**
    ```bash
    chmod +x DomainInfoSec.sh
    ```

3.  **Run the script:**

    * **Interactive Mode (prompts for domain):**
        ```bash
        ./DomainInfoSec.sh
        ```
    * **Direct Mode (provide domain as argument):**
        ```bash
        ./DomainInfoSec.sh example.com
        ```

The script will then check for dependencies and proceed through the information gathering steps, printing color-coded output for each section. You will be prompted before running optional scans (Nmap, Subdomain Enumeration) that require external tools or specific authorization.

## Output

The script uses ANSI color codes for readability:
* **Blue:** Section Headers
* **Cyan:** Informational messages
* **Yellow:** Labels, Warnings, Prompts
* **Green:** Success messages, Found items (IPs, secure headers)
* **Red:** Errors, Not found items (insecure headers), Failures

## Suggestions for Further Analysis

The script concludes by suggesting more specialized tools for deeper analysis, such as:

* `whatweb`: For detailed web technology detection.
* `wafw00f`: For Web Application Firewall detection.
* `nmap scripts` (`--script vuln`): For basic vulnerability scanning (Use with extreme caution and permission!).
* `nuclei`: Template-based vulnerability scanner.
* `Shodan.io`: Search engine for internet-connected devices.

## License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

## Author

* **Het Mehta**

## Contributing

Contributions, issues, and feature requests are welcome. Please create an issue or pull request if you have suggestions for improvement.
