#!/bin/bash

# ==============================================
# IMPROVED VULNERABLE DEVICE SCANNER
# Author: Jyomama28
# Version: 2.0
# ==============================================

# ==== LEGAL DISCLAIMER ====
echo -e "\033[1;31m[!] WARNING: UNAUTHORIZED SCANNING IS ILLEGAL! SCAN AT YOUR OWN RISK!\033[0m"
echo -e "\033[1;33m[!] This script must only be used on networks you own or have explicit permission to scan. Scan illegally at your own risk.\033[0m"
read -p "Do you confirm you have legal authorization? (y/N): " legal_confirm
if [[ "$legal_confirm" != "y" && "$legal_confirm" != "Y" ]]; then
    echo -e "\033[1;31m[!] Aborting. You must have permission to scan.\033[0m"
    exit 1
fi

# ==== CONFIGURATION ====
RED="\033[1;31m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
NC="\033[0m"

OUTDIR="vulnscan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR" || { echo -e "${RED}[-] Failed to create output directory.${NC}"; exit 1; }

# ==== CHECK DEPENDENCIES ====
echo -e "${CYAN}[*] Checking dependencies...${NC}"

required_tools=("shodan" "nmap" "curl" "jq")
missing_tools=()

for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done

if [[ ${#missing_tools[@]} -gt 0 ]]; then
    echo -e "${RED}[-] Missing tools: ${missing_tools[*]}${NC}"
    echo -e "${YELLOW}[!] Install missing tools with:"
    echo "      pip install shodan (for Shodan CLI)"
    echo "      sudo apt install nmap curl jq (for other tools)"
    echo -e "${NC}"
    exit 1
fi

# ==== CHECK SHODAN API KEY ====
if ! shodan info &> /dev/null; then
    echo -e "${RED}[-] Shodan API key not set. Get one from https://developer.shodan.io/${NC}"
    echo -e "${YELLOW}[!] Run: shodan init YOUR_API_KEY${NC}"
    exit 1
fi

# ==== PROXY/VPN CHECK ====
echo -e "${CYAN}[*] Checking network anonymity...${NC}"
PUBLIC_IP=$(curl -s ifconfig.me)
echo -e "${YELLOW}[!] Your public IP: $PUBLIC_IP${NC}"
read -p "Are you using a VPN/proxy? (y/N): " vpn_confirm
if [[ "$vpn_confirm" != "y" && "$vpn_confirm" != "Y" ]]; then
    echo -e "${RED}[-] WARNING: Scanning without a VPN/proxy exposes your real IP!${NC}"
    read -p "Continue anyway? (y/N): " continue_anyway
    if [[ "$continue_anyway" != "y" && "$continue_anyway" != "Y" ]]; then
        exit 1
    fi
fi

# ==== SCAN CONFIGURATION ====
SERVICES=("ftp" "telnet" "smb" "vnc" "rdp" "mongodb" "elasticsearch" "ssh")
MAX_RESULTS=10  # Limit to avoid excessive queries
NMAP_ARGS="-sV -Pn -T4 --script vulners,exploit,vuln --min-rate 100"  # Faster & more thorough

# ==== MAIN SCAN LOOP ====
echo -e "${CYAN}[*] Starting scan...${NC}"

for service in "${SERVICES[@]}"; do
    echo -e "${GREEN}[+] Searching for open $service ports...${NC}"
    shodan search --limit "$MAX_RESULTS" "port:$service" --fields ip_str,port,org,hostnames 2> /dev/null > "$OUTDIR/${service}_raw.txt" || {
        echo -e "${RED}[-] Shodan query failed for $service${NC}"
        continue
    }

    if [[ ! -s "$OUTDIR/${service}_raw.txt" ]]; then
        echo -e "${YELLOW}[!] No $service hosts found.${NC}"
        continue
    fi

    while read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        port=$(echo "$line" | awk '{print $2}')
        
        echo -e "${CYAN}[>] Scanning $ip:$port with Nmap...${NC}"
        nmap $NMAP_ARGS -p "$port" "$ip" -oN "$OUTDIR/${service}_nmap_$ip.txt" || {
            echo -e "${RED}[-] Nmap scan failed for $ip:$port${NC}"
            continue
        }
        
        # Extract CVEs if found
        if grep -q "CVE-" "$OUTDIR/${service}_nmap_$ip.txt"; then
            echo -e "${RED}[!] Found CVEs in $ip:$port${NC}"
            grep "CVE-" "$OUTDIR/${service}_nmap_$ip.txt" > "$OUTDIR/${service}_cves_$ip.txt"
        fi
    done < "$OUTDIR/${service}_raw.txt"
done

# ==== CLEANUP & SUMMARY ====
echo -e "${GREEN}[✓] Scan complete. Results saved in $OUTDIR/${NC}"
echo -e "${YELLOW}[!] Remember to delete sensitive data after analysis.${NC}"

exit 0