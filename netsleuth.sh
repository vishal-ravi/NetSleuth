#!/usr/bin/env bash

# ==============================================================
# NetSleuth v4
# Network Intelligence & Reconnaissance Toolkit
#
# Authorized security testing / personal lab use only.
#
# Features:
#   - Dependency detection
#   - Optional dependency installation
#   - Host discovery
#   - DNS / RDAP / WHOIS
#   - ARP / MAC / vendor
#   - TCP / UDP discovery
#   - Service/version detection
#   - OS fingerprinting
#   - SMB / NetBIOS
#   - SSH
#   - HTTP / HTTPS
#   - TLS
#   - RDP
#   - FTP
#   - LDAP
#   - SNMP
#   - UPnP
#   - mDNS
#   - Database detection
#   - ASN
#   - GeoIP
#   - Traceroute
#   - Shodan
#   - Censys
#   - Optional PCAP capture
#   - Optional Nmap vulnerability enumeration
#   - Structured reports
#
# Usage:
#   ./netsleuth.sh <IP> [OPTION]
#
# ==============================================================

set -u
set -o pipefail

VERSION="4.0"

# ==============================================================
# COLORS
# ==============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# ==============================================================
# GLOBAL VARIABLES
# ==============================================================

IP=""
MODE="quick"

SAVE_REPORT=false
INSTALL_DEPS=false

REPORT_DIR=""
RAW_DIR=""
ENRICH_DIR=""
PCAP_DIR=""

HOSTNAME="Unknown"
MAC="Unknown"
VENDOR="Unknown"

PACKAGE_MANAGER=""

MISSING_REQUIRED=()
MISSING_OPTIONAL=()
SKIPPED_MODULES=()

# ==============================================================
# OUTPUT FUNCTIONS
# ==============================================================

banner() {

    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                         NetSleuth                            ║"
    echo "║          Network Intelligence & Recon Toolkit               ║"
    echo "║                         v$VERSION                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

section() {

    echo
    echo -e "${CYAN}=============================================================="
    echo " $1"
    echo -e "==============================================================${NC}"
}

info() {
    echo -e "${BLUE}[*]${NC} $1"
}

success() {
    echo -e "${GREEN}[+]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error_msg() {
    echo -e "${RED}[-]${NC} $1"
}

found() {
    echo -e "${MAGENTA}[FOUND]${NC} $1"
}

skip_module() {

    local MODULE="$1"

    warning "Skipping module: $MODULE"

    SKIPPED_MODULES+=("$MODULE")
}

# ==============================================================
# USAGE
# ==============================================================

usage() {

cat <<EOF

NetSleuth v$VERSION

Usage:

    $0 <IP> [OPTION]

Modes:

    --quick
        Basic host discovery + TCP top ports.

    --deep
        Extensive authorized reconnaissance.

    --all
        Full collection.

    --passive
        DNS/RDAP/WHOIS/GeoIP/API intelligence.
        No active port scanning.

    --udp
        UDP discovery.

    --web
        HTTP/HTTPS/TLS analysis.

    --smb
        SMB/NetBIOS analysis.

    --ssh
        SSH analysis.

    --vuln
        Nmap vulnerability-category enumeration.

    --pcap
        Capture packets involving the target.

    --shodan
        Shodan enrichment.

    --censys
        Censys enrichment.

Options:

    --report
        Save results.

    --install-deps
        Install missing dependencies automatically
        using the detected package manager.

Examples:

    $0 192.168.1.10 --quick

    sudo $0 192.168.1.10 --deep --report

    sudo $0 192.168.1.10 --all --install-deps

    $0 8.8.8.8 --passive --report

    sudo $0 192.168.1.10 --pcap --report

Environment variables:

    SHODAN_API_KEY
    CENSYS_API_TOKEN
    CENSYS_ORG_ID

EOF
}

# ==============================================================
# COMMAND CHECK
# ==============================================================

has_cmd() {

    command -v "$1" >/dev/null 2>&1
}

# ==============================================================
# PACKAGE MANAGER DETECTION
# ==============================================================

detect_package_manager() {

    if has_cmd apt-get; then
        PACKAGE_MANAGER="apt"

    elif has_cmd dnf; then
        PACKAGE_MANAGER="dnf"

    elif has_cmd yum; then
        PACKAGE_MANAGER="yum"

    elif has_cmd pacman; then
        PACKAGE_MANAGER="pacman"

    elif has_cmd zypper; then
        PACKAGE_MANAGER="zypper"

    else
        PACKAGE_MANAGER="unknown"
    fi

    info "Package manager: $PACKAGE_MANAGER"
}

# ==============================================================
# PACKAGE INSTALLATION
# ==============================================================

install_package() {

    local PACKAGE="$1"

    case "$PACKAGE_MANAGER" in

        apt)

            sudo apt-get update
            sudo apt-get install -y "$PACKAGE"
            ;;

        dnf)

            sudo dnf install -y "$PACKAGE"
            ;;

        yum)

            sudo yum install -y "$PACKAGE"
            ;;

        pacman)

            sudo pacman -Sy --noconfirm "$PACKAGE"
            ;;

        zypper)

            sudo zypper --non-interactive install "$PACKAGE"
            ;;

        *)

            error_msg "Cannot automatically install $PACKAGE."
            return 1
            ;;
    esac
}

# ==============================================================
# DEPENDENCY MAP
# ==============================================================

declare -A TOOL_PACKAGE

TOOL_PACKAGE[nmap]="nmap"
TOOL_PACKAGE[curl]="curl"
TOOL_PACKAGE[ping]="iputils-ping"
TOOL_PACKAGE[ip]="iproute2"
TOOL_PACKAGE[awk]="gawk"
TOOL_PACKAGE[grep]="grep"
TOOL_PACKAGE[sed]="sed"
TOOL_PACKAGE[whois]="whois"
TOOL_PACKAGE[dig]="dnsutils"
TOOL_PACKAGE[host]="dnsutils"
TOOL_PACKAGE[nbtscan]="nbtscan"
TOOL_PACKAGE[openssl]="openssl"
TOOL_PACKAGE[traceroute]="traceroute"
TOOL_PACKAGE[tracepath]="iputils"
TOOL_PACKAGE[tcpdump]="tcpdump"
TOOL_PACKAGE[whatweb]="whatweb"
TOOL_PACKAGE[jq]="jq"
TOOL_PACKAGE[timeout]="coreutils"

# ==============================================================
# DEPENDENCY PREFLIGHT
# ==============================================================

check_dependencies() {

    section "DEPENDENCY PREFLIGHT"

    detect_package_manager

    local REQUIRED_TOOLS=(
        nmap
        curl
        ping
        ip
        awk
        grep
        sed
    )

    local OPTIONAL_TOOLS=(
        whois
        dig
        host
        nbtscan
        openssl
        traceroute
        tracepath
        tcpdump
        whatweb
        jq
        timeout
    )

    echo
    info "Checking required tools..."

    MISSING_REQUIRED=()

    for TOOL in "${REQUIRED_TOOLS[@]}"; do

        if has_cmd "$TOOL"; then

            echo -e "    ${GREEN}✓${NC} $TOOL"

        else

            echo -e "    ${RED}✗${NC} $TOOL"

            MISSING_REQUIRED+=("$TOOL")

        fi

    done

    echo
    info "Checking optional tools..."

    MISSING_OPTIONAL=()

    for TOOL in "${OPTIONAL_TOOLS[@]}"; do

        if has_cmd "$TOOL"; then

            echo -e "    ${GREEN}✓${NC} $TOOL"

        else

            echo -e "    ${YELLOW}○${NC} $TOOL"

            MISSING_OPTIONAL+=("$TOOL")

        fi

    done

    # ----------------------------------------------------------
    # Install missing dependencies
    # ----------------------------------------------------------

    if [ "$INSTALL_DEPS" = true ]; then

        section "INSTALLING MISSING DEPENDENCIES"

        if [ "$EUID" -eq 0 ]; then
            SUDO=""
        else
            SUDO="sudo"
        fi

        if [ "$PACKAGE_MANAGER" = "unknown" ]; then

            error_msg "No supported package manager found."

        else

            for TOOL in "${MISSING_REQUIRED[@]}"; do

                PACKAGE="${TOOL_PACKAGE[$TOOL]:-$TOOL}"

                info "Installing $TOOL -> $PACKAGE"

                if $SUDO true 2>/dev/null; then
                    install_package "$PACKAGE" || true
                fi

            done

            for TOOL in "${MISSING_OPTIONAL[@]}"; do

                PACKAGE="${TOOL_PACKAGE[$TOOL]:-$TOOL}"

                info "Installing optional tool $TOOL -> $PACKAGE"

                if $SUDO true 2>/dev/null; then
                    install_package "$PACKAGE" || true
                fi

            done

        fi

        # Re-check after installation.

        echo
        info "Rechecking dependencies..."

        MISSING_REQUIRED=()

        for TOOL in "${REQUIRED_TOOLS[@]}"; do

            if ! has_cmd "$TOOL"; then
                MISSING_REQUIRED+=("$TOOL")
            fi

        done

        if [ ${#MISSING_REQUIRED[@]} -gt 0 ]; then

            error_msg "Required dependencies still missing:"

            printf '    %s\n' "${MISSING_REQUIRED[@]}"

            exit 1
        fi
    fi

    # ----------------------------------------------------------
    # Required dependency failure
    # ----------------------------------------------------------

    if [ ${#MISSING_REQUIRED[@]} -gt 0 ]; then

        error_msg "Required dependencies are missing."

        echo
        echo "Run:"
        echo
        echo "    sudo $0 $IP $MODE --install-deps"
        echo
        echo "Or install them manually."

        exit 1
    fi

    success "Required dependencies available."

    if [ ${#MISSING_OPTIONAL[@]} -gt 0 ]; then

        warning "Some optional tools are missing."
        warning "Modules requiring them will be skipped automatically."

    fi
}

# ==============================================================
# MODULE TOOL CHECK
# ==============================================================

require_tools() {

    local MODULE="$1"
    shift

    local MISSING=()

    for TOOL in "$@"; do

        if ! has_cmd "$TOOL"; then
            MISSING+=("$TOOL")
        fi

    done

    if [ ${#MISSING[@]} -gt 0 ]; then

        warning "$MODULE requires:"
        printf '    %s\n' "${MISSING[@]}"

        skip_module "$MODULE"

        return 1
    fi

    return 0
}

# ==============================================================
# IP VALIDATION
# ==============================================================

validate_ipv4() {

    if [[ ! "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then

        error_msg "Invalid IPv4 address: $IP"

        exit 1
    fi

    IFS='.' read -r A B C D <<< "$IP"

    for OCTET in "$A" "$B" "$C" "$D"; do

        if (( OCTET < 0 || OCTET > 255 )); then

            error_msg "Invalid IPv4 address."

            exit 1
        fi

    done
}

# ==============================================================
# REPORT
# ==============================================================

prepare_report() {

    local DATE

    DATE=$(date +%Y%m%d_%H%M%S)

    REPORT_DIR="reports/${IP}_${DATE}"

    RAW_DIR="$REPORT_DIR/raw"
    ENRICH_DIR="$REPORT_DIR/enrichment"
    PCAP_DIR="$REPORT_DIR/pcap"

    mkdir -p \
        "$RAW_DIR" \
        "$ENRICH_DIR" \
        "$PCAP_DIR"

    success "Report directory:"
    echo "    $REPORT_DIR"
}

# ==============================================================
# SAVE COMMAND
# ==============================================================

run_save() {

    local FILE="$1"
    shift

    if [ "$SAVE_REPORT" = true ]; then

        "$@" 2>&1 | tee "$RAW_DIR/$FILE"

    else

        "$@"

    fi
}

# ==============================================================
# IP CLASSIFICATION
# ==============================================================

classify_ip() {

    section "IP CLASSIFICATION"

    if [[ "$IP" =~ ^10\. ]]; then

        echo "Private network: 10.0.0.0/8"

    elif [[ "$IP" =~ ^192\.168\. ]]; then

        echo "Private network: 192.168.0.0/16"

    elif [[ "$IP" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then

        echo "Private network: 172.16.0.0/12"

    elif [[ "$IP" =~ ^127\. ]]; then

        echo "Loopback"

    else

        echo "Public IPv4 address"

    fi
}

# ==============================================================
# HOST DISCOVERY
# ==============================================================

host_discovery() {

    if ! require_tools "Host Discovery" nmap ping; then
        return
    fi

    section "HOST DISCOVERY"

    echo "Target: $IP"

    info "Testing ICMP..."

    if ping -c 3 -W 2 "$IP" >/dev/null 2>&1; then

        success "Host responded to ICMP."

        ping -c 3 -W 2 "$IP" 2>/dev/null |
            tail -n 4

    else

        warning "No ICMP response."

    fi

    echo
    info "Nmap discovery..."

    run_save "host-discovery.txt" \
        nmap -Pn -sn "$IP"
}

# ==============================================================
# DNS
# ==============================================================

dns_reverse() {

    if ! require_tools "Reverse DNS" dig; then
        return
    fi

    section "REVERSE DNS"

    local PTR

    PTR=$(dig +short -x "$IP" 2>/dev/null | sed 's/\.$//' | head -n 1)

    if [ -n "$PTR" ]; then

        HOSTNAME="$PTR"

        found "Hostname: $HOSTNAME"

    else

        echo "No PTR record."

    fi

    if [ "$SAVE_REPORT" = true ]; then

        echo "Hostname: $HOSTNAME" \
            > "$ENRICH_DIR/reverse-dns.txt"

    fi
}

# ==============================================================
# ARP / MAC
# ==============================================================

arp_information() {

    if ! require_tools "ARP/MAC" ip; then
        return
    fi

    section "ARP / MAC"

    local NEIGHBOR

    NEIGHBOR=$(ip neigh show "$IP" 2>/dev/null || true)

    echo "$NEIGHBOR"

    MAC=$(echo "$NEIGHBOR" |
        awk '{for(i=1;i<=NF;i++) if ($i ~ /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/) print $i}' |
        head -n 1)

    if [ -n "$MAC" ]; then

        found "MAC: $MAC"

    else

        echo "MAC: unavailable"

    fi

    if [ -n "${MAC:-}" ] && has_cmd curl; then

        VENDOR=$(curl -fsS \
            --max-time 5 \
            "https://api.macvendors.com/$MAC" \
            2>/dev/null || true)

        if [ -n "$VENDOR" ]; then

            found "Vendor: $VENDOR"

        fi
    fi

    if [ "$SAVE_REPORT" = true ]; then

        {
            echo "Neighbor: $NEIGHBOR"
            echo "MAC: ${MAC:-Unknown}"
            echo "Vendor: ${VENDOR:-Unknown}"

        } > "$ENRICH_DIR/mac.txt"

    fi
}

# ==============================================================
# TCP
# ==============================================================

tcp_scan() {

    if ! require_tools "TCP Scan" nmap; then
        return
    fi

    section "TCP PORT DISCOVERY"

    info "Top 1000 TCP ports..."

    run_save "tcp-top1000.txt" \
        nmap -Pn -T3 --top-ports 1000 --reason "$IP"
}

# ==============================================================
# FULL TCP
# ==============================================================

tcp_full_scan() {

    if ! require_tools "Full TCP Scan" nmap; then
        return
    fi

    section "FULL TCP SCAN"

    info "Scanning TCP 1-65535..."

    run_save "tcp-full.txt" \
        nmap -Pn -T3 -p- --reason "$IP"
}

# ==============================================================
# SERVICES
# ==============================================================

service_detection() {

    if ! require_tools "Service Detection" nmap; then
        return
    fi

    section "SERVICE DETECTION"

    run_save "services.txt" \
        nmap -Pn \
        -sV \
        --version-light \
        --reason \
        "$IP"
}

# ==============================================================
# DEEP SERVICES
# ==============================================================

service_deep() {

    if ! require_tools "Deep Service Detection" nmap; then
        return
    fi

    section "DEEP SERVICE FINGERPRINTING"

    run_save "services-detailed.txt" \
        nmap -Pn \
        -sV \
        --version-all \
        --reason \
        "$IP"
}

# ==============================================================
# OS
# ==============================================================

os_detection() {

    if ! require_tools "OS Detection" nmap; then
        return
    fi

    section "OPERATING SYSTEM"

    if [ "$EUID" -ne 0 ]; then

        warning "OS detection requires root."

        skip_module "OS Detection"

        return

    fi

    run_save "os.txt" \
        nmap -Pn \
        -O \
        --osscan-guess \
        --reason \
        "$IP"
}

# ==============================================================
# UDP
# ==============================================================

udp_scan() {

    if ! require_tools "UDP Scan" nmap; then
        return
    fi

    section "UDP DISCOVERY"

    if [ "$EUID" -ne 0 ]; then

        warning "UDP scan may require root."

    fi

    run_save "udp.txt" \
        nmap -Pn \
        -sU \
        --top-ports 50 \
        --reason \
        "$IP"
}

# ==============================================================
# SMB
# ==============================================================

smb_scan() {

    if ! require_tools "SMB Enumeration" nmap; then
        return
    fi

    section "SMB / WINDOWS"

    run_save "smb.txt" \
        nmap -Pn \
        -p 135,139,445 \
        --script \
        smb-os-discovery,\
smb-protocols,\
smb2-security-mode,\
smb2-time \
        "$IP"

    if has_cmd nbtscan; then

        run_save "netbios.txt" \
            nbtscan "$IP"

    else

        warning "nbtscan unavailable; NetBIOS module skipped."

        skip_module "NetBIOS"

    fi
}

# ==============================================================
# SSH
# ==============================================================

ssh_scan() {

    if ! require_tools "SSH Enumeration" nmap; then
        return
    fi

    section "SSH"

    run_save "ssh.txt" \
        nmap -Pn \
        -p 22 \
        --script \
        ssh-hostkey,\
ssh2-enum-algos,\
ssh-auth-methods \
        "$IP"
}

# ==============================================================
# WEB
# ==============================================================

web_scan() {

    if ! require_tools "Web Enumeration" nmap curl; then
        return
    fi

    section "WEB"

    run_save "web.txt" \
        nmap -Pn \
        -p 80,443,8000,8080,8081,8443 \
        --script \
        http-title,\
http-server-header,\
http-methods,\
http-security-headers \
        "$IP"

    for PORT in 80 8000 8080 8081; do

        echo
        echo "----- HTTP:$PORT -----"

        curl -I \
            -sS \
            --connect-timeout 3 \
            --max-time 5 \
            "http://$IP:$PORT" \
            2>/dev/null || true

    done

    for PORT in 443 8443; do

        echo
        echo "----- HTTPS:$PORT -----"

        curl -k \
            -I \
            -sS \
            --connect-timeout 3 \
            --max-time 5 \
            "https://$IP:$PORT" \
            2>/dev/null || true

    done
}

# ==============================================================
# TLS
# ==============================================================

tls_scan() {

    if ! require_tools "TLS Enumeration" nmap; then
        return
    fi

    section "TLS / SSL"

    run_save "tls.txt" \
        nmap -Pn \
        -p 443,8443 \
        --script \
        ssl-cert,\
ssl-enum-ciphers \
        "$IP"

    if has_cmd openssl; then

        for PORT in 443 8443; do

            echo
            echo "Certificate on port $PORT"

            timeout 8 \
                openssl s_client \
                -connect "$IP:$PORT" \
                -servername "$IP" \
                </dev/null 2>/dev/null |
                openssl x509 \
                -noout \
                -subject \
                -issuer \
                -dates \
                -serial \
                -fingerprint \
                -sha256 \
                2>/dev/null || true

        done

    else

        warning "OpenSSL unavailable."

        skip_module "OpenSSL certificate parsing"

    fi
}

# ==============================================================
# WHOIS
# ==============================================================

whois_information() {

    if ! require_tools "WHOIS" whois; then
        return
    fi

    section "WHOIS"

    run_save "whois.txt" \
        whois "$IP"
}

# ==============================================================
# RDAP / ASN
# ==============================================================

asn_information() {

    if ! require_tools "RDAP/ASN" curl; then
        return
    fi

    section "RDAP / ASN"

    local OUTPUT

    OUTPUT=$(curl -fsS \
        --max-time 15 \
        "https://rdap.org/ip/$IP" \
        2>/dev/null || true)

    if [ -n "$OUTPUT" ]; then

        echo "$OUTPUT"

        if [ "$SAVE_REPORT" = true ]; then
            echo "$OUTPUT" > "$ENRICH_DIR/rdap.json"
        fi

    else

        warning "RDAP returned no data."

    fi

    if has_cmd nmap; then

        run_save "asn.txt" \
            nmap -Pn \
            --script asn-query \
            "$IP"

    fi
}

# ==============================================================
# GEOIP
# ==============================================================

geoip_information() {

    if ! require_tools "GeoIP" curl; then
        return
    fi

    section "GEOIP"

    local OUTPUT

    OUTPUT=$(curl -fsS \
        --max-time 10 \
        "https://ipinfo.io/$IP/json" \
        2>/dev/null || true)

    if [ -n "$OUTPUT" ]; then

        echo "$OUTPUT"

        if [ "$SAVE_REPORT" = true ]; then
            echo "$OUTPUT" > "$ENRICH_DIR/geoip.json"
        fi

    else

        warning "GeoIP lookup failed."

    fi
}

# ==============================================================
# TRACE
# ==============================================================

trace_route() {

    section "NETWORK PATH"

    if has_cmd traceroute; then

        run_save "traceroute.txt" \
            traceroute -n -m 15 "$IP"

    elif has_cmd tracepath; then

        run_save "tracepath.txt" \
            tracepath "$IP"

    elif has_cmd nmap; then

        run_save "traceroute.txt" \
            nmap -Pn --traceroute -p 80 "$IP"

    else

        skip_module "Traceroute"

    fi
}

# ==============================================================
# RDP
# ==============================================================

rdp_scan() {

    if ! require_tools "RDP" nmap; then
        return
    fi

    section "RDP"

    run_save "rdp.txt" \
        nmap -Pn \
        -p 3389 \
        --script \
        rdp-enum-encryption,\
rdp-ntlm-info \
        "$IP"
}

# ==============================================================
# FTP
# ==============================================================

ftp_scan() {

    if ! require_tools "FTP" nmap; then
        return
    fi

    section "FTP"

    run_save "ftp.txt" \
        nmap -Pn \
        -p 21 \
        --script \
        ftp-syst,\
ftp-anon \
        "$IP"
}

# ==============================================================
# LDAP
# ==============================================================

ldap_scan() {

    if ! require_tools "LDAP" nmap; then
        return
    fi

    section "LDAP"

    run_save "ldap.txt" \
        nmap -Pn \
        -p 389,636 \
        --script ldap-rootdse \
        "$IP"
}

# ==============================================================
# DATABASES
# ==============================================================

database_scan() {

    if ! require_tools "Database Discovery" nmap; then
        return
    fi

    section "DATABASE DISCOVERY"

    run_save "databases.txt" \
        nmap -Pn \
        -p 1433,1521,3306,5432,6379,9200,27017 \
        --script \
        mysql-info,\
ms-sql-info,\
pgsql-info,\
redis-info,\
mongodb-info \
        "$IP"
}

# ==============================================================
# SNMP
# ==============================================================

snmp_scan() {

    if ! require_tools "SNMP" nmap; then
        return
    fi

    section "SNMP"

    run_save "snmp.txt" \
        nmap -Pn \
        -sU \
        -p 161 \
        --script snmp-info \
        "$IP"
}

# ==============================================================
# UPnP
# ==============================================================

upnp_scan() {

    if ! require_tools "UPnP" nmap; then
        return
    fi

    section "UPnP"

    run_save "upnp.txt" \
        nmap -Pn \
        -sU \
        -p 1900 \
        --script upnp-info \
        "$IP"
}

# ==============================================================
# mDNS
# ==============================================================

mdns_scan() {

    if ! require_tools "mDNS" nmap; then
        return
    fi

    section "mDNS"

    run_save "mdns.txt" \
        nmap -Pn \
        -sU \
        -p 5353 \
        --script dns-service-discovery \
        "$IP"
}

# ==============================================================
# WHATWEB
# ==============================================================

whatweb_scan() {

    if ! require_tools "WhatWeb" whatweb; then
        return
    fi

    section "WEB TECHNOLOGY"

    run_save "whatweb.txt" \
        whatweb \
        "http://$IP"
}

# ==============================================================
# SHODAN
# ==============================================================

shodan_lookup() {

    if ! require_tools "Shodan" curl; then
        return
    fi

    section "SHODAN"

    if [ -z "${SHODAN_API_KEY:-}" ]; then

        warning "SHODAN_API_KEY not set."

        echo "Set it with:"
        echo
        echo 'export SHODAN_API_KEY="YOUR_KEY"'

        skip_module "Shodan"

        return
    fi

    local OUTPUT

    OUTPUT=$(curl -fsS \
        --max-time 20 \
        "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_API_KEY" \
        2>/dev/null || true)

    if [ -n "$OUTPUT" ]; then

        echo "$OUTPUT"

        if [ "$SAVE_REPORT" = true ]; then
            echo "$OUTPUT" > "$ENRICH_DIR/shodan.json"
        fi

    else

        warning "Shodan returned no result."

    fi
}

# ==============================================================
# CENSYS
# ==============================================================

censys_lookup() {

    if ! require_tools "Censys" curl; then
        return
    fi

    section "CENSYS"

    if [ -z "${CENSYS_API_TOKEN:-}" ]; then

        warning "CENSYS_API_TOKEN not set."

        skip_module "Censys"

        return
    fi

    local URL="https://api.platform.censys.io/v3/global/asset/host/$IP"
    local OUTPUT

    OUTPUT=$(curl -fsS \
        --max-time 20 \
        "$URL" \
        -H "Authorization: Bearer $CENSYS_API_TOKEN" \
        -H "Accept: application/vnd.censys.api.v3.host.v1+json" \
        2>/dev/null || true)

    if [ -n "$OUTPUT" ]; then

        echo "$OUTPUT"

        if [ "$SAVE_REPORT" = true ]; then
            echo "$OUTPUT" > "$ENRICH_DIR/censys.json"
        fi

    else

        warning "Censys returned no result."

    fi
}

# ==============================================================
# PACKET CAPTURE
# ==============================================================

packet_capture() {

    if ! require_tools "Packet Capture" tcpdump ip; then
        return
    fi

    section "PACKET CAPTURE"

    if [ "$EUID" -ne 0 ]; then

        warning "Packet capture requires root."

        skip_module "Packet Capture"

        return
    fi

    if [ "$SAVE_REPORT" = false ]; then

        warning "Packet capture requires report mode."

        skip_module "Packet Capture"

        return
    fi

    local INTERFACE

    INTERFACE=$(ip route get "$IP" 2>/dev/null |
        awk '
        {
            for(i=1;i<=NF;i++)
                if($i=="dev")
                    print $(i+1)
        }' |
        head -n 1)

    if [ -z "$INTERFACE" ]; then

        warning "Could not determine interface."

        skip_module "Packet Capture"

        return
    fi

    local FILE="$PCAP_DIR/${IP}.pcap"

    info "Interface: $INTERFACE"
    info "Output: $FILE"

    echo
    echo "Press CTRL+C to stop."
    echo

    tcpdump \
        -i "$INTERFACE" \
        -nn \
        -s 0 \
        "host $IP" \
        -w "$FILE"
}

# ==============================================================
# VULNERABILITY ENUMERATION
# ==============================================================

vulnerability_scan() {

    if ! require_tools "Vulnerability Enumeration" nmap; then
        return
    fi

    section "VULNERABILITY ENUMERATION"

    warning "Only use this against authorized systems."

    run_save "vulnerabilities.txt" \
        nmap -Pn \
        -sV \
        --script vuln \
        "$IP"
}

# ==============================================================
# LOCAL NETWORK
# ==============================================================

local_network() {

    if ! require_tools "Local Network" ip; then
        return
    fi

    section "LOCAL NETWORK"

    echo "Interfaces:"
    ip -br addr

    echo
    echo "Routes:"
    ip route

    echo
    echo "Neighbors:"
    ip neigh

    if [ "$SAVE_REPORT" = true ]; then

        {
            echo "INTERFACES"
            ip -br addr

            echo
            echo "ROUTES"
            ip route

            echo
            echo "NEIGHBORS"
            ip neigh

        } > "$RAW_DIR/local-network.txt"

    fi
}

# ==============================================================
# SECURITY SUMMARY
# ==============================================================

security_summary() {

    section "SECURITY OBSERVATIONS"

    local FILE="$RAW_DIR/services.txt"

    if [ ! -f "$FILE" ]; then
        FILE="$RAW_DIR/services-detailed.txt"
    fi

    if [ ! -f "$FILE" ]; then

        warning "No service report available."

        return
    fi

    echo

    declare -A SERVICE_NAMES

    SERVICE_NAMES[21]="FTP"
    SERVICE_NAMES[22]="SSH"
    SERVICE_NAMES[23]="Telnet"
    SERVICE_NAMES[25]="SMTP"
    SERVICE_NAMES[53]="DNS"
    SERVICE_NAMES[80]="HTTP"
    SERVICE_NAMES[135]="MSRPC"
    SERVICE_NAMES[139]="NetBIOS"
    SERVICE_NAMES[443]="HTTPS"
    SERVICE_NAMES[445]="SMB"
    SERVICE_NAMES[161]="SNMP"
    SERVICE_NAMES[389]="LDAP"
    SERVICE_NAMES[636]="LDAPS"
    SERVICE_NAMES[1433]="MSSQL"
    SERVICE_NAMES[3306]="MySQL"
    SERVICE_NAMES[3389]="RDP"
    SERVICE_NAMES[5432]="PostgreSQL"
    SERVICE_NAMES[6379]="Redis"
    SERVICE_NAMES[9200]="Elasticsearch"
    SERVICE_NAMES[27017]="MongoDB"

    for PORT in "${!SERVICE_NAMES[@]}"; do

        if grep -qE "^${PORT}/tcp[[:space:]]+open|^${PORT}/udp[[:space:]]+open" "$FILE"; then

            echo "  [OPEN] $PORT -> ${SERVICE_NAMES[$PORT]}"

        fi

    done
}

# ==============================================================
# SKIPPED MODULE REPORT
# ==============================================================

skipped_report() {

    section "MODULE STATUS"

    if [ ${#SKIPPED_MODULES[@]} -eq 0 ]; then

        success "No modules were skipped."

        return
    fi

    warning "Skipped modules:"

    for MODULE in "${SKIPPED_MODULES[@]}"; do

        echo "    - $MODULE"

    done

    if [ "$SAVE_REPORT" = true ]; then

        printf '%s\n' "${SKIPPED_MODULES[@]}" \
            > "$REPORT_DIR/skipped-modules.txt"

    fi
}

# ==============================================================
# FINAL REPORT
# ==============================================================

generate_summary() {

    section "FINAL SUMMARY"

    echo
    echo "Target IP : $IP"
    echo "Hostname  : $HOSTNAME"
    echo "MAC       : ${MAC:-Unknown}"
    echo "Vendor    : ${VENDOR:-Unknown}"
    echo "Mode      : $MODE"
    echo "Time      : $(date)"

    echo

    security_summary

    skipped_report

    if [ "$SAVE_REPORT" = true ]; then

        cat > "$REPORT_DIR/README.txt" <<EOF
==============================================================
NetSleuth Report
==============================================================

Target IP:
$IP

Hostname:
$HOSTNAME

MAC:
${MAC:-Unknown}

Vendor:
${VENDOR:-Unknown}

Mode:
$MODE

Generated:
$(date)

Report:
$REPORT_DIR

==============================================================
Directories
==============================================================

raw/
    Raw scanner output.

enrichment/
    DNS, RDAP, GeoIP, Shodan, Censys etc.

pcap/
    Packet captures when enabled.

==============================================================
EOF

        echo
        success "Report saved to:"
        echo "    $REPORT_DIR"

    fi

    echo
    success "NetSleuth completed."
}

# ==============================================================
# QUICK
# ==============================================================

run_quick() {

    classify_ip
    host_discovery
    dns_reverse
    arp_information
    tcp_scan
    service_detection
}

# ==============================================================
# DEEP
# ==============================================================

run_deep() {

    classify_ip

    host_discovery
    dns_reverse
    arp_information

    tcp_scan
    tcp_full_scan
    service_detection
    service_deep
    os_detection

    udp_scan

    smb_scan
    ssh_scan
    web_scan
    tls_scan

    rdp_scan
    ftp_scan
    ldap_scan

    database_scan

    snmp_scan
    upnp_scan
    mdns_scan

    dns_information 2>/dev/null || true

    whois_information
    asn_information
    geoip_information

    trace_route

    local_network
}

# ==============================================================
# MAIN
# ==============================================================

if [ "$#" -lt 1 ]; then

    banner
    usage

    exit 1
fi

# --------------------------------------------------------------
# Parse arguments
# --------------------------------------------------------------

IP="$1"

for ARG in "$@"; do

    case "$ARG" in

        --quick)
            MODE="quick"
            ;;

        --deep)
            MODE="deep"
            ;;

        --all)
            MODE="all"
            ;;

        --passive)
            MODE="passive"
            ;;

        --udp)
            MODE="udp"
            ;;

        --web)
            MODE="web"
            ;;

        --smb)
            MODE="smb"
            ;;

        --ssh)
            MODE="ssh"
            ;;

        --vuln)
            MODE="vuln"
            ;;

        --pcap)
            MODE="pcap"
            ;;

        --shodan)
            MODE="shodan"
            ;;

        --censys)
            MODE="censys"
            ;;

        --report)
            SAVE_REPORT=true
            ;;

        --install-deps)
            INSTALL_DEPS=true
            ;;

        --help|-h)
            banner
            usage
            exit 0
            ;;

    esac

done

# --------------------------------------------------------------
# Validate
# --------------------------------------------------------------

validate_ipv4

banner

# --------------------------------------------------------------
# Dependencies FIRST
# --------------------------------------------------------------

check_dependencies

# --------------------------------------------------------------
# Prepare report
# --------------------------------------------------------------

if [ "$SAVE_REPORT" = true ] || [ "$MODE" != "quick" ]; then

    SAVE_REPORT=true
    prepare_report

fi

# ==============================================================
# EXECUTION
# ==============================================================

case "$MODE" in

    quick)

        run_quick
        ;;

    deep)

        run_deep
        ;;

    all)

        run_deep

        whatweb_scan

        shodan_lookup
        censys_lookup

        echo
        info "Full scan completed."

        echo
        echo "For packet capture run separately:"
        echo
        echo "sudo $0 $IP --pcap --report"

        ;;

    passive)

        classify_ip
        dns_reverse
        whois_information
        asn_information
        geoip_information
        shodan_lookup
        censys_lookup
        ;;

    udp)

        classify_ip
        udp_scan
        ;;

    web)

        classify_ip
        dns_reverse
        web_scan
        tls_scan
        whatweb_scan
        ;;

    smb)

        classify_ip
        dns_reverse
        smb_scan
        ;;

    ssh)

        classify_ip
        dns_reverse
        ssh_scan
        ;;

    vuln)

        classify_ip
        host_discovery
        service_detection
        vulnerability_scan
        ;;

    pcap)

        classify_ip
        packet_capture
        ;;

    shodan)

        classify_ip
        shodan_lookup
        ;;

    censys)

        classify_ip
        censys_lookup
        ;;

esac

# --------------------------------------------------------------
# Final report
# --------------------------------------------------------------

generate_summary