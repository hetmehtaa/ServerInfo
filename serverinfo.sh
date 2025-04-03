#!/usr/bin/env bash

# ==============================================================================
# Script Name:    ServerInfo.sh 
# Description:    Comprehensive script to gather cybersecurity-related
#                 information for a given domain. Targets Linux & macOS.
# Author:         Het Mehta | hetmehta.com
# License:        MIT License (or choose another OSI approved license)
# Version:        1.0.0
# Date:           2025-04-03
# Disclaimer:     *** LEGAL DISCLAIMER ***
#                 This script is intended for educational purposes and for use
#                 ONLY on systems and networks where you have explicit, prior,
#                 written authorization. Unauthorized scanning or testing of
#                 systems is illegal and unethical. The author assumes NO
#                 liability for misuse of this script. Use responsibly.
# ==============================================================================

# --- Configuration & Colors ---
RESET='\033[0m'
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD_RED='\033[1;31m'
BOLD_YELLOW='\033[1;33m'
BOLD_BLUE='\033[1;34m'
BOLD_MAGENTA='\033[1;35m'
BOLD_CYAN='\033[1;36m'

# --- Global Variables ---
TARGET_DOMAIN=""
IP_ADDRESS=""
OS_TYPE=""
# Flags for optional tools found
NMAP_FOUND=false
SUBFINDER_FOUND=false
ASSETFINDER_FOUND=false

# --- Utility Functions ---
print_header() {
    echo -e "\n${BOLD_BLUE}===== $1 =====${RESET}"
}

print_warning() {
    echo -e "${BOLD_YELLOW}[!] Warning:${RESET} $1"
}

print_error() {
    echo -e "${BOLD_RED}[X] Error:${RESET} $1" >&2
}

print_info() {
    echo -e "${BOLD_CYAN}[*] Info:${RESET} $1"
}

print_success() {
    echo -e "${BOLD_GREEN}[+] Success:${RESET} $1"
}

# Function to check if a command exists and provide install hints
check_command() {
    local cmd=$1
    if ! command -v "$cmd" &> /dev/null; then
        print_error "'$cmd' command not found. Please install it."
        echo -e "   ${YELLOW}Installation hints:${RESET}"
        echo -e "     Debian/Ubuntu: sudo apt update && sudo apt install <package_name>"
        echo -e "     Fedora/CentOS: sudo dnf install <package_name> or sudo yum install <package_name>"
        echo -e "     macOS (Homebrew): brew install <package_name>"
        echo -e "   ${YELLOW}(Replace <package_name> with appropriate package, e.g., 'dnsutils' for dig/host, 'nmap', 'subfinder', 'assetfinder', 'whois')${RESET}"
        # Decide if the script should exit if a critical command is missing
        # For now, just warn for most, but could exit for e.g. dig/curl
        # Example: [[ "$cmd" == "dig" ]] && exit 1
        return 1 # Indicate command not found
    fi
    # Optionally set flags for optional tools
    case "$cmd" in
        nmap) NMAP_FOUND=true ;;
        subfinder) SUBFINDER_FOUND=true ;;
        assetfinder) ASSETFINDER_FOUND=true ;;
    esac
    return 0 # Indicate command found
}

get_os_type() {
    case "$(uname -s)" in
        Linux*)     OS_TYPE='Linux';;
        Darwin*)    OS_TYPE='macOS';;
        *)          OS_TYPE='UNKNOWN';;
    esac
    print_info "Detected OS: $OS_TYPE"
}

# --- Information Gathering Functions ---

get_ip_address() {
    print_header "1. IP Address & Reverse DNS"
    print_info "Resolving IP Address (A Record) for $TARGET_DOMAIN..."
    IP_ADDRESS=$(dig +short A "$TARGET_DOMAIN" | head -n 1)
    if [[ -n "$IP_ADDRESS" ]]; then
        echo -e " ${YELLOW}IP Address:${RESET} ${GREEN}$IP_ADDRESS${RESET}"
        run_reverse_dns
    else
        print_error "Could not resolve an IPv4 address for $TARGET_DOMAIN."
        # Consider exiting if IP is crucial for subsequent steps
        # exit 1
    fi
}

run_reverse_dns() {
    if [[ -z "$IP_ADDRESS" ]]; then return; fi
    print_info "Performing Reverse DNS Lookup for $IP_ADDRESS..."
    local reverse_dns
    # `host` command output parsing seems relatively consistent
    reverse_dns=$(host "$IP_ADDRESS" | awk '/domain name pointer/ {print $NF}')
    if [[ -n "$reverse_dns" ]]; then
        echo -e " ${YELLOW}Reverse DNS (PTR):${RESET} ${GREEN}${reverse_dns%.}${RESET}" # Remove trailing dot if present
    else
        print_warning "Reverse DNS lookup failed or no PTR record found."
    fi
}

run_dns_queries() {
    print_header "2. Common DNS Records"
    local records=("MX" "NS" "TXT" "SOA")
    for record_type in "${records[@]}"; do
        echo -e " ${YELLOW}${record_type} Records:${RESET}"
        local output
        output=$(dig +short "$record_type" "$TARGET_DOMAIN")
        if [[ -n "$output" ]]; then
            echo "$output" | sed 's/^/      /'
        else
            echo -e "      ${RED}Query failed or no ${record_type} records found.${RESET}"
        fi
    done
}

check_dns_security() {
    print_header "3. DNS Security Records"
    # SPF Check (within TXT)
    echo -e " ${YELLOW}SPF Record (TXT):${RESET}"
    local spf_record
    spf_record=$(dig +short TXT "$TARGET_DOMAIN" | grep 'v=spf1')
    if [[ -n "$spf_record" ]]; then
        echo "$spf_record" | sed 's/^/      /'
    else
        print_warning "No SPF record found in TXT records."
    fi

    # DMARC Check
    echo -e " ${YELLOW}DMARC Record (_dmarc TXT):${RESET}"
    local dmarc_record
    dmarc_record=$(dig +short TXT "_dmarc.$TARGET_DOMAIN")
     if [[ -n "$dmarc_record" ]]; then
        echo "$dmarc_record" | sed 's/^/      /'
    else
        print_warning "No DMARC record found for _dmarc.$TARGET_DOMAIN."
    fi

    # DNSKEY Check (Basic presence)
    echo -e " ${YELLOW}DNSKEY Record (DNSSEC):${RESET}"
    local dnskey_record
    dnskey_record=$(dig +short DNSKEY "$TARGET_DOMAIN")
    if [[ -n "$dnskey_record" ]]; then
        print_success "DNSKEY records found, DNSSEC might be enabled."
        # Can optionally print keys, but they are long
        # echo "$dnskey_record" | head -n 2 | sed 's/^/      /' && echo "      ..."
    else
        print_warning "No DNSKEY records found. DNSSEC likely not enabled or not published."
    fi
}

run_whois() {
    print_header "4. WHOIS Information"
    if check_command "whois"; then
        print_info "Querying WHOIS servers for $TARGET_DOMAIN..."
        whois "$TARGET_DOMAIN"
        print_warning "WHOIS details may be incomplete or redacted for privacy."
    else
        print_error "Cannot perform WHOIS lookup."
    fi
}

run_curl_headers() {
    print_header "5. HTTP/HTTPS Headers & Security"
    local url=$1
    local protocol=${url%%:*} # http or https
    print_info "Checking headers for $url ..."
    # Fetch headers using curl
    local headers
    headers=$(curl -sSL --connect-timeout 10 -I "$url") # Increased timeout slightly

    if [[ $? -eq 0 && -n "$headers" ]]; then
        echo -e "${GREEN}--- Headers from $url ---${RESET}"
        echo "$headers"
        echo -e "${GREEN}---------------------------------${RESET}"
        check_http_security_headers "$headers" # Pass headers to security check function
    else
        print_error "Failed to connect or retrieve headers from $url."
    fi
}

check_http_security_headers() {
    local headers="$1"
    print_info "Checking for common security headers..."
    local found_any=false

    check_header() {
        local header_name=$1
        local header_pattern="^${header_name}:"
        if echo "$headers" | grep -iqE "$header_pattern"; then
            echo -e "   ${GREEN}[✔]${RESET} ${YELLOW}${header_name}:${RESET} Found"
            found_any=true
        else
            echo -e "   ${RED}[✘]${RESET} ${YELLOW}${header_name}:${RESET} Not Found"
        fi
    }

    check_header "Strict-Transport-Security"
    check_header "Content-Security-Policy"
    check_header "X-Frame-Options"
    check_header "X-Content-Type-Options"
    check_header "Referrer-Policy"
    check_header "Permissions-Policy" # Formerly Feature-Policy

    if ! $found_any; then
        print_warning "No common security headers detected in this response."
    fi
}


run_ssl_check() {
    print_header "6. SSL/TLS Certificate Details"
    print_info "Attempting to retrieve SSL Certificate from $TARGET_DOMAIN:443..."
    # Use timeout command if available for better control, otherwise rely on openssl timeout (less reliable)
    local openssl_cmd="openssl s_client -servername \"$TARGET_DOMAIN\" -connect \"$TARGET_DOMAIN:443\" -showcerts < /dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates -serial -fingerprint -noout 2>/dev/null"
    local cert_info

    if command -v timeout &> /dev/null; then
         cert_info=$(timeout 10s bash -c "$openssl_cmd")
    else
        # Less reliable timeout mechanism without `timeout` command
         cert_info=$(bash -c "$openssl_cmd")
         print_warning "Consider installing 'timeout' utility for better SSL check reliability."
    fi


    if [[ -n "$cert_info" ]]; then
        echo "$cert_info" | sed -e "s/^subject=/   ${YELLOW}Subject:${RESET} /" \
                           -e "s/^issuer=/   ${YELLOW}Issuer:${RESET} /" \
                           -e "s/^notBefore=/   ${YELLOW}Valid From:${RESET} /" \
                           -e "s/^notAfter=/   ${YELLOW}Valid Until:${RESET} /" \
                           -e "s/^serial=/   ${YELLOW}Serial Number:${RESET} /" \
                           -e "s/^SHA1 Fingerprint=/   ${YELLOW}SHA1 Fingerprint:${RESET} /"
    else
        print_error "Could not retrieve valid SSL certificate info from $TARGET_DOMAIN:443."
        print_warning "(Maybe HTTPS/Port 443 is not available, connection timed out, or cert is invalid)."
    fi
}

run_traceroute() {
    print_header "7. Network Path (Traceroute)"
    if check_command "traceroute"; then
        print_info "Running traceroute to $TARGET_DOMAIN (might take a minute)..."
        local traceroute_opts=""
        # Basic OS-specific flags for potentially faster/standardized trace
        if [[ "$OS_TYPE" == "Linux" ]]; then
            # Use ICMP echo requests on Linux, limit probes per hop
             traceroute_opts="-I -q 1 -w 2" # ICMP, 1 query/hop, 2 sec wait
        elif [[ "$OS_TYPE" == "macOS" ]]; then
            # macOS uses ICMP by default, limit probes per hop
             traceroute_opts="-q 1 -w 2" # 1 query/hop, 2 sec wait
        fi
         traceroute $traceroute_opts "$TARGET_DOMAIN"
    else
        print_error "Cannot perform traceroute."
    fi
}

run_ping() {
    print_header "8. Basic Reachability (Ping)"
    print_info "Pinging $TARGET_DOMAIN (4 packets)..."
    # Ping command is fairly standard for -c count
    if ping -c 4 "$TARGET_DOMAIN"; then
        print_success "Host appears to be reachable."
    else
        print_error "Host did not respond to ping (may be down or blocking ICMP)."
    fi
}

# --- Optional Scans (Require Confirmation & Tools) ---

run_port_scan() {
    print_header "9. Port Scan (Optional - Requires Nmap)"
    if ! $NMAP_FOUND; then
        print_warning "Nmap not found. Skipping port scan."
        echo -e "   ${YELLOW}Install nmap ('apt install nmap', 'dnf install nmap', 'brew install nmap') to enable.${RESET}"
        return
    fi

    read -p "$(echo -e ${BOLD_YELLOW}"Run a basic Nmap port scan on $TARGET_DOMAIN? (Top 100 ports, requires permissions!) [y/N]: "${RESET})" -n 1 -r
    echo # Move to a new line
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Skipping Nmap scan."
        return
    fi

    print_warning "Running Nmap. Ensure you have authorization! This may take time."
    # -F: Fast scan (Top 100 ports)
    # -T4: Aggressive timing (can be noisy)
    # Consider adding -Pn if ping fails but you still want to scan.
    nmap -F -T4 "$TARGET_DOMAIN"
}

run_subdomain_scan() {
    print_header "10. Subdomain Enumeration (Optional)"
    local tool_to_use=""

    if $SUBFINDER_FOUND; then
        tool_to_use="subfinder"
    elif $ASSETFINDER_FOUND; then
        tool_to_use="assetfinder"
    else
        print_warning "Neither 'subfinder' nor 'assetfinder' found. Skipping subdomain enumeration."
        echo -e "   ${YELLOW}Install ('brew install subfinder', 'apt install subfinder', etc.) to enable.${RESET}"
        return
    fi

    read -p "$(echo -e ${BOLD_YELLOW}"Run $tool_to_use to find subdomains for $TARGET_DOMAIN? (Uses public sources) [y/N]: "${RESET})" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Skipping subdomain scan."
        return
    fi

    print_info "Running $tool_to_use - this might take a few moments..."
    case "$tool_to_use" in
        subfinder)
            subfinder -d "$TARGET_DOMAIN" -silent # -silent for cleaner output
            ;;
        assetfinder)
            assetfinder --subs-only "$TARGET_DOMAIN"
            ;;
    esac
     print_success "Subdomain scan finished."
}

suggest_external_tools() {
    print_header "Further Analysis Suggestions"
    print_info "For deeper insights, consider using specialized tools:"
    echo -e " - ${YELLOW}Web Technology Detection:${RESET} whatweb ($TARGET_DOMAIN) (Install: 'apt install whatweb', 'brew install whatweb')"
    echo -e " - ${YELLOW}Web Application Firewall (WAF) Detection:${RESET} wafw00f -a https://$TARGET_DOMAIN (Install: 'pip install wafw00f', 'brew install wafw00f')"
    echo -e " - ${YELLOW}Vulnerability Scanning:${RESET} Nmap scripts (nmap -sV --script vuln $TARGET_DOMAIN), Nuclei, OpenVAS, Nessus (Requires expertise & permission!)"
    echo -e " - ${YELLOW}Public Exposure Data:${RESET} Check Shodan.io for $IP_ADDRESS or $TARGET_DOMAIN"
}


# ==============================================================================
#                              MAIN EXECUTION
# ==============================================================================

# --- Initial Setup & Checks ---
get_os_type
# Check essential commands first
check_command "dig" || exit 1
check_command "host" || exit 1
check_command "curl" || exit 1
check_command "openssl" || exit 1
check_command "ping" # Usually present, but check
# Check optional commands and set flags
check_command "whois"
check_command "traceroute"
check_command "nmap"
check_command "subfinder"
check_command "assetfinder"


# --- Get Target Domain ---
# Basic argument parsing example (can be expanded)
if [[ $# -gt 0 ]]; then
    TARGET_DOMAIN=$1
    print_info "Target domain set from argument: $TARGET_DOMAIN"
else
     read -p "$(echo -e ${BOLD_YELLOW}"Enter the target domain name (e.g., google.com): "${RESET})" TARGET_DOMAIN
fi

if [[ -z "$TARGET_DOMAIN" ]]; then
    print_error "No target domain provided."
    exit 1
fi

# Remove potential http(s):// prefix
TARGET_DOMAIN=$(echo "$TARGET_DOMAIN" | sed -e 's|^https\?://||' -e 's|/.*$||')
print_info "Standardized target: $TARGET_DOMAIN"


# --- Print Banner ---
echo -e "\n${BOLD_MAGENTA}### Starting Security Information Gathering for: $TARGET_DOMAIN ###${RESET}"
echo -e "${BOLD_RED}### REMINDER: Ensure you have authorization before scanning! ###${RESET}"
echo -e "${CYAN}-----------------------------------------------------------------${RESET}"
read -p "$(echo -e ${BOLD_YELLOW}"Press [Enter] to begin scans..."${RESET})"


# --- Execute Information Gathering Functions ---
get_ip_address           # Section 1 (includes Reverse DNS)
run_dns_queries          # Section 2
check_dns_security       # Section 3
run_whois                # Section 4
# Run Header check for both HTTP and HTTPS if possible
run_curl_headers "http://$TARGET_DOMAIN"  # Section 5 (HTTP Part)
run_curl_headers "https://$TARGET_DOMAIN" # Section 5 (HTTPS Part & Security Headers)
run_ssl_check            # Section 6
run_traceroute           # Section 7
run_ping                 # Section 8
run_port_scan            # Section 9 (Optional)
run_subdomain_scan       # Section 10 (Optional)


# --- Final Suggestions & Completion ---
suggest_external_tools

echo -e "\n${BOLD_GREEN}### Information gathering script finished for $TARGET_DOMAIN ###${RESET}"

exit 0