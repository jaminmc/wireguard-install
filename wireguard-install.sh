#!/bin/bash

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

RED='\033[0;31m'      # Error messages
ORANGE='\033[0;33m'   # Warning messages  
GREEN='\033[0;32m'    # Success messages
BLUE='\033[0;34m'     # Info messages
YELLOW='\033[1;33m'   # Highlighted warnings
NC='\033[0m'          # No color (reset)

# Color utility functions
error() {
    echo -e "${RED}$1${NC}"
}

warning() {
    echo -e "${ORANGE}$1${NC}"
}

success() {
    echo -e "${GREEN}$1${NC}"
}

info() {
    echo -e "${BLUE}$1${NC}"
}

highlight() {
    echo -e "${YELLOW}$1${NC}"
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	function openvzErr() {
		echo "OpenVZ is not supported"
		exit 1
	}
	function lxcErr() {
		highlight "LXC is in Beta."
		warning "WireGuard can technically run in an LXC container,"
		warning "but the kernel module has to be installed on the host,"
		warning "the container has to be run with some specific parameters"
		warning "and only the tools need to be installed in the container."
		echo ""
		warning "If WireGuard is not in your kernel,"
		warning "this will give the option to try to install BoringTun instead"
		echo ""
		read -rp "Do you want to continue anyway? [y/n]: " -e CONTINUE_LXC
		CONTINUE_LXC=${CONTINUE_LXC:-n}
		if [[ $CONTINUE_LXC != 'y' && $CONTINUE_LXC != 'Y' ]]; then
			exit 1
		fi
		success "Continuing with LXC environment..."
		
		# Check if WireGuard kernel module is available
		if lsmod | grep -q wireguard; then
			success "WireGuard kernel module is loaded and available."
			LXC_HASWIREGUARD=true
		elif [ -e "/sys/module/wireguard" ]; then
			success "WireGuard kernel module is available (built into kernel)."
			LXC_HASWIREGUARD=true
		elif [ -e "/lib/modules/$(uname -r)/kernel/net/wireguard/wireguard.ko" ] || [ -e "/lib/modules/$(uname -r)/kernel/net/wireguard/wireguard.ko.xz" ]; then
			success "WireGuard kernel module is available on disk."
			LXC_HASWIREGUARD=true
		else
			# Try to create a temporary test interface to verify kernel module functionality
			info "Testing WireGuard kernel module functionality..."
			if ip link add dev wg-test type wireguard 2>/dev/null; then
				success "WireGuard kernel module is functional (test interface created successfully)."
				# Clean up the test interface
				ip link del dev wg-test 2>/dev/null
				LXC_HASWIREGUARD=true
			else
				highlight "Warning: WireGuard kernel module is not available or functional in this LXC container."
				warning "You can install BoringTun (userspace WireGuard implementation) instead."
				LXC_HASWIREGUARD=false
				
				# Check if TUN device is available (required for BoringTun)
				if [[ ! -e /dev/net/tun ]]; then
					echo ""
					error "TUN device (/dev/net/tun) is not available."
					echo ""
					warning "BoringTun requires a TUN device to function. This device is typically:"
					warning "  - Created by the 'tun' kernel module"
					warning "  - Available in most VPS environments"
					warning "  - Required for userspace VPN implementations"
					echo ""
					info "To enable the TUN device, you can try:"
					info "  1. Load the tun module: modprobe tun"
					info "  2. Check if it's available: ls -la /dev/net/tun"
					info "  3. If the module doesn't exist, contact your hosting provider"
					echo ""
					error "Cannot proceed without TUN device. Exiting..."
					exit 1
				fi
				
				success "TUN device is available. BoringTun can be installed."
				echo ""
				read -rp "Do you want to install BoringTun? [y/n]: " -e INSTALL_BORINGTUN
				INSTALL_BORINGTUN=${INSTALL_BORINGTUN:-n}
				if [[ $INSTALL_BORINGTUN != 'y' && $INSTALL_BORINGTUN != 'Y' ]]; then
					error "WireGuard kernel module is required. Exiting..."
					exit 1
				fi
				INSTALL_BORINGTUN="y"
				success "BoringTun will be installed instead of WireGuard kernel module..."
			fi
		fi
	}
	if command -v virt-what &>/dev/null; then
		if [ "$(virt-what)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(virt-what)" == "lxc" ]; then
			lxcErr
		fi
	else
		if [ "$(systemd-detect-virt)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(systemd-detect-virt)" == "lxc" ]; then
			lxcErr
		fi
	fi
}

is_non_routable() {
    local ip=$1
    # Convert IP to integer for comparison
    ip_to_int() {
        local a b c d
        IFS=. read -r a b c d <<< "$1"
        echo $(( (a<<24) + (b<<16) + (c<<8) + d ))
    }

    ip_int=$(ip_to_int "$ip")

    # Define non-routable ranges as integer boundaries
    declare -A ranges=(
        ["10.0.0.0/8"]="167772160 184549375"          # RFC 1918
        ["172.16.0.0/12"]="2886729728 2887778303"     # RFC 1918
        ["192.168.0.0/16"]="3232235520 3232301055"    # RFC 1918
        ["100.64.0.0/10"]="1681915904 1686110207"     # CGNAT (RFC 6598)
        ["192.0.0.0/24"]="3221225472 3221225727"      # 464XLAT/CLAT (RFC 7335)
        ["0.0.0.0/8"]="0 16777215"                    # This network
        ["127.0.0.0/8"]="2130706432 2147483647"       # Loopback
        ["169.254.0.0/16"]="2851995648 2852061183"    # Link-local
        ["192.0.2.0/24"]="3221225984 3221226239"      # TEST-NET-1
        ["198.51.100.0/24"]="3325256704 3325256959"   # TEST-NET-2
        ["203.0.113.0/24"]="3399667712 3399667967"    # TEST-NET-3
        ["224.0.0.0/4"]="3758096384 4026531839"       # Multicast
        ["240.0.0.0/4"]="4026531840 4294967295"       # Reserved (Class E)
    )

    for range in "${!ranges[@]}"; do
        read -r start end <<< "${ranges[$range]}"
        if [ "$ip_int" -ge "$start" ] && [ "$ip_int" -le "$end" ]; then
            echo "IP $ip is non-routable ($range)"
            return 0
        fi
    done
    echo "IP $ip is routable"
    return 1
}

is_valid_ip() {
    local ip=$1
    # Check if it's a valid IPv4 address
    if [[ $ip =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
        return 0
    fi
    # Check if it's a valid IPv6 address
    if [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]] || \
       [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,6}:[0-9a-fA-F]{0,4}$ ]] || \
       [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,5}(:[0-9a-fA-F]{0,4}){1,2}$ ]] || \
       [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,4}(:[0-9a-fA-F]{0,4}){1,3}$ ]] || \
       [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,3}(:[0-9a-fA-F]{0,4}){1,4}$ ]] || \
       [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,2}(:[0-9a-fA-F]{0,4}){1,5}$ ]] || \
       [[ $ip =~ ^[0-9a-fA-F]{0,4}:(:[0-9a-fA-F]{0,4}){1,6}$ ]] || \
       [[ $ip =~ ^:(:[0-9a-fA-F]{0,4}){1,7}$ ]]; then
        return 0
    fi
    return 1
}

get_system_dns() {
    local dns1=""
    local dns2=""
    
    # Try to get DNS from resolv.conf
    if [[ -f /etc/resolv.conf ]]; then
        # Get first two nameserver entries
        dns1=$(grep -E "^nameserver[[:space:]]+" /etc/resolv.conf | head -1 | awk '{print $2}')
        dns2=$(grep -E "^nameserver[[:space:]]+" /etc/resolv.conf | head -2 | tail -1 | awk '{print $2}')
    fi
    
    # If resolv.conf doesn't have valid IPs, try systemd-resolve
    if [[ -z "$dns1" ]] || ! is_valid_ip "$dns1"; then
        if command -v systemd-resolve &>/dev/null; then
            dns1=$(systemd-resolve --status | grep -A 5 "DNS Servers:" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}' | head -1)
            dns2=$(systemd-resolve --status | grep -A 5 "DNS Servers:" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}' | head -2 | tail -1)
        fi
    fi
    
    # If still no valid DNS, try network manager
    if [[ -z "$dns1" ]] || ! is_valid_ip "$dns1"; then
        if command -v nmcli &>/dev/null; then
            dns1=$(nmcli dev show | grep DNS | head -1 | awk '{print $2}')
            dns2=$(nmcli dev show | grep DNS | head -2 | tail -1 | awk '{print $2}')
        fi
    fi
    
    # Return the detected DNS servers
    echo "$dns1 $dns2"
}

get_external_ip() {
    local external_ip=""
    
    # Try curl first (more common)
    if command -v curl &>/dev/null; then
        external_ip=$(curl -s --max-time 10 --connect-timeout 5 \
            -H "User-Agent: WireGuard-Installer/1.0" \
            https://ipinfo.io/ip 2>/dev/null)
        
        # If curl fails, try alternative services
        if [[ -z "$external_ip" ]] || ! is_valid_ip "$external_ip"; then
            external_ip=$(curl -s --max-time 10 --connect-timeout 5 \
                -H "User-Agent: WireGuard-Installer/1.0" \
                https://icanhazip.com 2>/dev/null | tr -d '\n\r')
        fi
        
        if [[ -z "$external_ip" ]] || ! is_valid_ip "$external_ip"; then
            external_ip=$(curl -s --max-time 10 --connect-timeout 5 \
                -H "User-Agent: WireGuard-Installer/1.0" \
                https://checkip.amazonaws.com 2>/dev/null | tr -d '\n\r')
        fi
    fi
    
    # If curl failed or not available, try wget
    if [[ -z "$external_ip" ]] || ! is_valid_ip "$external_ip"; then
        if command -v wget &>/dev/null; then
            external_ip=$(wget -qO- --timeout=10 --tries=1 \
                --user-agent="WireGuard-Installer/1.0" \
                https://ipinfo.io/ip 2>/dev/null)
            
            if [[ -z "$external_ip" ]] || ! is_valid_ip "$external_ip"; then
                external_ip=$(wget -qO- --timeout=10 --tries=1 \
                    --user-agent="WireGuard-Installer/1.0" \
                    https://icanhazip.com 2>/dev/null | tr -d '\n\r')
            fi
        fi
    fi
    
    echo "$external_ip"
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 11 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 20 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 20.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 37 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 37 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 Stream, AlmaLinux 8, or Rocky Linux 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			apk update && apk add virt-what
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkOS

}

function installQuestions() {
	local IP_FAMILY
	local EXTERNAL_IP
	local DNS_CHOICE
	local DNS_CONFIRM

	checkVirt
	success "Welcome to the WireGuard installer!"
	info "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	info "I need to ask you a few questions before starting the setup."
	info "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP_V4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	SERVER_PUB_IP_V6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	
	HAS_IPV4=false
	HAS_IPV6=false
	HAS_ROUTABLE_IPV4=false
	IP_FAMILY=""
	
	# Check if IPv4 is available (both public and private)
	if [[ -n ${SERVER_PUB_IP_V4} ]]; then
		if is_non_routable "${SERVER_PUB_IP_V4}"; then
			HAS_IPV4=true  # Still has IPv4, just not routable
			HAS_ROUTABLE_IPV4=false
		else
			HAS_IPV4=true
			HAS_ROUTABLE_IPV4=true
		fi
	fi
	
	# Check if IPv6 is available
	if [[ -n ${SERVER_PUB_IP_V6} ]]; then
		HAS_IPV6=true
	fi
	
	# Determine which IP to suggest as default
	if [[ ${HAS_ROUTABLE_IPV4} == true && ${HAS_IPV6} == true ]]; then
		# Both available, prefer IPv4 for better compatibility
		DEFAULT_PUB_IP="${SERVER_PUB_IP_V4}"
		IP_FAMILY="ipv4"
	elif [[ ${HAS_ROUTABLE_IPV4} == true ]]; then
		# Only routable IPv4 available
		DEFAULT_PUB_IP="${SERVER_PUB_IP_V4}"
		IP_FAMILY="ipv4"
	elif [[ ${HAS_IPV6} == true ]]; then
		# Only IPv6 available or IPv4 is non-routable
		DEFAULT_PUB_IP="${SERVER_PUB_IP_V6}"
		IP_FAMILY="ipv6"
	else
		# No public IPs detected
		DEFAULT_PUB_IP=""
		IP_FAMILY=""
	fi
	if [[ -z ${DEFAULT_PUB_IP} ]]; then
		echo ""
		highlight "No public IP address was automatically detected."
		warning "This might happen if:"
		warning "  - You're behind NAT"
		warning "  - You're in a private network"
		warning "  - Your server uses a different network configuration"
		echo ""
		
		# Try to detect external IP address
		info "Attempting to detect your external public IP address..."
		EXTERNAL_IP=$(get_external_ip)
		
		if [[ -n "$EXTERNAL_IP" ]] && is_valid_ip "$EXTERNAL_IP"; then
			success "Detected external public IP: $EXTERNAL_IP"
			DEFAULT_PUB_IP="$EXTERNAL_IP"
			success "This will be used as the default suggestion."
			echo ""
			highlight "IMPORTANT: Since you're behind NAT, you will need to:"
			warning "  1. Port forward UDP port [WIREGUARD_PORT] from your router to this server"
			warning "  2. Use the external IP address ($EXTERNAL_IP) for client connections"
		else
			error "Could not automatically detect external IP address."
			warning "Please enter your server's public IP address manually."
			info "You can find it by visiting: https://whatismyipaddress.com/"
			echo ""
			highlight "IMPORTANT: Since you're behind NAT, you will need to:"
			warning "  1. Port forward UDP port [WIREGUARD_PORT] from your router to this server"
			warning "  2. Use the external IP address for client connections"
		fi
	fi
	
	# Display concise IP detection summary before user input
	info "Network detection:"
	if [[ -n ${SERVER_PUB_IP_V4} ]]; then
		if [[ ${HAS_ROUTABLE_IPV4} == true ]]; then
			echo "  $(success "IPv4: ${SERVER_PUB_IP_V4} (${SERVER_NIC_V4}) - public")"
		else
			echo "  $(warning "IPv4: ${SERVER_PUB_IP_V4} (${SERVER_NIC_V4}) - not publicly routable")"
		fi
	fi
	if [[ -n ${SERVER_PUB_IP_V6} ]]; then
		echo "  $(success "IPv6: ${SERVER_PUB_IP_V6} (${SERVER_NIC_V6})")"
	fi
	if [[ -z ${SERVER_PUB_IP_V4} && -z ${SERVER_PUB_IP_V6} ]]; then
		echo "  $(highlight "No local public IP addresses detected")"
		if [[ -n "$EXTERNAL_IP" ]] && is_valid_ip "$EXTERNAL_IP"; then
			echo "  $(info "External IP: $EXTERNAL_IP (detected via internet)")"
		fi
	fi
	echo ""
	
	until is_valid_ip "${SERVER_PUB_IP}"; do
		read -rp "IPv4 or IPv6 public address: " -e -i "${DEFAULT_PUB_IP}" SERVER_PUB_IP
	done

	# Detect public interfaces for both IPv4 and IPv6
	SERVER_NIC_V4="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	SERVER_NIC_V6="$(ip -6 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	
	# Set the primary interface based on the detected IP family
	if [[ ${IP_FAMILY} == "ipv4" ]]; then
		SERVER_NIC="${SERVER_NIC_V4}"
	else
		SERVER_NIC="${SERVER_NIC_V6}"
	fi
	# Fallback: if no interface found for the detected IP family, use the other family's interface
	if [[ -z "${SERVER_NIC}" ]]; then
		if [[ ${IP_FAMILY} == "ipv4" ]]; then
			SERVER_NIC="${SERVER_NIC_V6}"
		else
			SERVER_NIC="${SERVER_NIC_V4}"
		fi
	fi
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
	done

	# Generate random numbers for IPv4 and IPv6 addresses
	RANDOM_IPV4_SECOND=$(shuf -i0-254 -n1)
	RANDOM_IPV4_THIRD=$(shuf -i0-254 -n1)
	DEFAULT_IPV4="10.${RANDOM_IPV4_SECOND}.${RANDOM_IPV4_THIRD}.1"
	DEFAULT_IPV6="fd42:${RANDOM_IPV4_SECOND}:${RANDOM_IPV4_THIRD}::1"

	# Always prompt for IPv4 to prevent VPN leaks (even if server doesn't have IPv4)
	# This ensures clients are always routed through the VPN for IPv4 traffic
	until is_valid_ip "${SERVER_WG_IPV4}" && [[ ${SERVER_WG_IPV4} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; do
		read -rp "Server WireGuard IPv4: " -e -i "${DEFAULT_IPV4}" SERVER_WG_IPV4
	done

	# Always prompt for IPv6 to prevent VPN leaks (even if server doesn't have IPv6)
	# This ensures clients are always routed through the VPN for IPv6 traffic
	until is_valid_ip "${SERVER_WG_IPV6}" && [[ ${SERVER_WG_IPV6} =~ .*:.* ]]; do
		read -rp "Server WireGuard IPv6: " -e -i "${DEFAULT_IPV6}" SERVER_WG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Detect system DNS servers
	SYSTEM_DNS=$(get_system_dns)
	SYSTEM_DNS_1=$(echo "$SYSTEM_DNS" | awk '{print $1}')
	SYSTEM_DNS_2=$(echo "$SYSTEM_DNS" | awk '{print $2}')
	
	# Determine if system DNS is available and valid
	SYSTEM_DNS_AVAILABLE=false
	if [[ -n "$SYSTEM_DNS_1" ]] && is_valid_ip "$SYSTEM_DNS_1"; then
		SYSTEM_DNS_AVAILABLE=true
	fi
	
	# DNS server selection
	echo ""
	echo "DNS server options:"
	if [[ ${SYSTEM_DNS_AVAILABLE} == true ]]; then
		echo "1) System DNS servers: $SYSTEM_DNS_1${SYSTEM_DNS_2:+ and $SYSTEM_DNS_2}"
	else
		echo "1) System DNS servers: Not available"
	fi
	echo "2) Cloudflare DNS (1.1.1.1, 1.0.0.1)"
	echo "3) Google Public DNS (8.8.8.8, 8.8.4.4)"
	echo "4) Quad9 DNS (9.9.9.9, 149.112.112.112)"
	echo "5) Custom DNS servers"
	echo ""
	
	# Set DNS choices based on available IP families
	if [[ ${HAS_IPV4} == true ]]; then
		CLOUDflare_DNS_1="1.1.1.1"
		CLOUDflare_DNS_2="1.0.0.1"
		GOOGLE_DNS_1="8.8.8.8"
		GOOGLE_DNS_2="8.8.4.4"
		QUAD9_DNS_1="9.9.9.9"
		QUAD9_DNS_2="149.112.112.112"
	else
		# IPv6-only DNS servers
		CLOUDflare_DNS_1="2606:4700:4700::1111"
		CLOUDflare_DNS_2="2606:4700:4700::1001"
		GOOGLE_DNS_1="2001:4860:4860::8888"
		GOOGLE_DNS_2="2001:4860:4860::8844"
		QUAD9_DNS_1="2620:fe::fe"
		QUAD9_DNS_2="2620:fe::9"
	fi
	
	# DNS selection
	until [[ ${DNS_CHOICE} =~ ^[1-5]$ ]]; do
		if [[ ${SYSTEM_DNS_AVAILABLE} == true ]]; then
			read -rp "Select DNS option [1-5]: " -e -i "2" DNS_CHOICE
		else
			read -rp "Select DNS option [2-5]: " -e -i "2" DNS_CHOICE
		fi
	done
	
	# Set DNS servers based on selection
	case ${DNS_CHOICE} in
		1)
			if [[ ${SYSTEM_DNS_AVAILABLE} == true ]]; then
				CLIENT_DNS_1="${SYSTEM_DNS_1}"
				CLIENT_DNS_2="${SYSTEM_DNS_2}"
				echo "Using system DNS servers: $CLIENT_DNS_1${CLIENT_DNS_2:+ and $CLIENT_DNS_2}"
			else
				echo "System DNS not available, defaulting to Cloudflare DNS"
				CLIENT_DNS_1="${CLOUDflare_DNS_1}"
				CLIENT_DNS_2="${CLOUDflare_DNS_2}"
			fi
			;;
		2)
			CLIENT_DNS_1="${CLOUDflare_DNS_1}"
			CLIENT_DNS_2="${CLOUDflare_DNS_2}"
			echo "Using Cloudflare DNS: $CLIENT_DNS_1 and $CLIENT_DNS_2"
			;;
		3)
			CLIENT_DNS_1="${GOOGLE_DNS_1}"
			CLIENT_DNS_2="${GOOGLE_DNS_2}"
			echo "Using Google Public DNS: $CLIENT_DNS_1 and $CLIENT_DNS_2"
			;;
		4)
			CLIENT_DNS_1="${QUAD9_DNS_1}"
			CLIENT_DNS_2="${QUAD9_DNS_2}"
			echo "Using Quad9 DNS: $CLIENT_DNS_1 and $CLIENT_DNS_2"
			;;
		5)
			echo "Enter custom DNS servers:"
			until is_valid_ip "${CLIENT_DNS_1}"; do
				read -rp "First DNS resolver: " -e CLIENT_DNS_1
			done
			until is_valid_ip "${CLIENT_DNS_2}"; do
				read -rp "Second DNS resolver (optional): " -e CLIENT_DNS_2
				if [[ ${CLIENT_DNS_2} == "" ]]; then
					CLIENT_DNS_2="${CLIENT_DNS_1}"
				fi
			done
			;;
	esac
	
	# Final confirmation/override option
	echo ""
	echo "Selected DNS servers: $CLIENT_DNS_1${CLIENT_DNS_2:+ and $CLIENT_DNS_2}"
	read -rp "Press Enter to continue or type 'c' to change: " -e DNS_CONFIRM
	if [[ ${DNS_CONFIRM} == "c" || ${DNS_CONFIRM} == "C" ]]; then
		echo "Enter new DNS servers:"
		until is_valid_ip "${CLIENT_DNS_1}"; do
			read -rp "First DNS resolver: " -e CLIENT_DNS_1
		done
		until is_valid_ip "${CLIENT_DNS_2}"; do
			read -rp "Second DNS resolver (optional): " -e CLIENT_DNS_2
			if [[ ${CLIENT_DNS_2} == "" ]]; then
				CLIENT_DNS_2="${CLIENT_DNS_1}"
			fi
		done
		echo "Updated DNS servers: $CLIENT_DNS_1${CLIENT_DNS_2:+ and $CLIENT_DNS_2}"
	fi

	# Always set default ALLOWED_IPS to include both IPv4 and IPv6 to prevent VPN leaks
	# This ensures all client traffic (both IPv4 and IPv6) is routed through the VPN
	DEFAULT_ALLOWED_IPS="0.0.0.0/0,::/0"
	
	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i "${DEFAULT_ALLOWED_IPS}" ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="${DEFAULT_ALLOWED_IPS}"
		fi
	done

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

# Package management functions
install_packages() {
	local os=$1
	local packages=$2
	local boringtun=${3:-false}
	
	info "Installing packages for ${os}: ${packages}"
	
	case $os in
		'ubuntu'|'debian')
			info "Updating package lists..."
			if ! apt-get update; then
				error "Failed to update package lists for ${os}"
				return 1
			fi
			
			info "Installing packages: ${packages}"
			if ! apt-get install -y $packages; then
				error "Failed to install packages: ${packages}"
				error "Please check your internet connection and package repositories"
				return 1
			fi
			
			if [[ $boringtun == true ]]; then
				info "Installing BoringTun for ${os}..."
				if ! install_boringtun "${os}"; then
					error "Failed to install BoringTun"
					return 1
				fi
			fi
			;;
		'fedora')
			info "Installing packages: ${packages}"
			if ! dnf install -y $packages; then
				error "Failed to install packages: ${packages}"
				error "Please check your internet connection and package repositories"
				return 1
			fi
			
			if [[ $boringtun == true ]]; then
				info "Installing BoringTun for ${os}..."
				if ! install_boringtun "${os}"; then
					error "Failed to install BoringTun"
					return 1
				fi
			fi
			;;
		'centos'|'almalinux'|'rocky')
			info "Installing packages: ${packages}"
			if ! yum install -y $packages; then
				error "Failed to install packages: ${packages}"
				error "Please check your internet connection and package repositories"
				return 1
			fi
			
			if [[ $boringtun == true ]]; then
				info "Installing BoringTun for ${os}..."
				if ! install_boringtun "${os}"; then
					error "Failed to install BoringTun"
					return 1
				fi
			fi
			;;
		'oracle')
			info "Installing packages: ${packages}"
			if ! dnf install -y $packages; then
				error "Failed to install packages: ${packages}"
				error "Please check your internet connection and package repositories"
				return 1
			fi
			
			if [[ $boringtun == true ]]; then
				info "Installing BoringTun for ${os}..."
				if ! install_boringtun "${os}"; then
					error "Failed to install BoringTun"
					return 1
				fi
			fi
			;;
		'arch')
			info "Installing packages: ${packages}"
			if ! pacman -S --needed --noconfirm $packages; then
				error "Failed to install packages: ${packages}"
				error "Please check your internet connection and package repositories"
				return 1
			fi
			
			if [[ $boringtun == true ]]; then
				info "Installing BoringTun for ${os}..."
				if ! install_boringtun "${os}"; then
					error "Failed to install BoringTun"
					return 1
				fi
			fi
			;;
		'alpine')
			info "Updating package lists..."
			if ! apk update; then
				error "Failed to update package lists for ${os}"
				return 1
			fi
			
			info "Installing packages: ${packages}"
			if ! apk add $packages; then
				error "Failed to install packages: ${packages}"
				error "Please check your internet connection and package repositories"
				return 1
			fi
			
			if [[ $boringtun == true ]]; then
				info "Installing BoringTun for ${os}..."
				if ! install_boringtun "${os}"; then
					error "Failed to install BoringTun"
					return 1
				fi
			fi
			;;
		*)
			error "Unsupported operating system: ${os}"
			return 1
			;;
	esac
	
	success "Package installation completed successfully for ${os}"
	return 0
}

install_boringtun() {
	local os=$1
	
	# Install Rust and Cargo (except for Arch which has it in repos)
	if [[ $os != 'arch' ]]; then
		info "Installing Rust and Cargo..."
		if ! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; then
			error "Failed to install Rust and Cargo"
			error "Please check your internet connection and try again"
			return 1
		fi
		
		info "Sourcing Rust environment..."
		if ! source ~/.cargo/env; then
			error "Failed to source Rust environment"
			return 1
		fi
	fi
	
	# Install BoringTun via Cargo directly to /usr/local
	info "Installing BoringTun via Cargo..."
	if ! cargo install --root /usr/local boringtun-cli; then
		error "Failed to install BoringTun via Cargo"
		error "Please check your internet connection and Rust installation"
		return 1
	fi
	
	success "BoringTun installed successfully to /usr/local/bin/boringtun-cli"
	return 0
}

remove_packages() {
	local os=$1
	local packages=$2
	
	info "Removing packages for ${os}: ${packages}"
	
	case $os in
		'ubuntu'|'debian')
			if ! apt-get remove -y $packages; then
				error "Failed to remove packages: ${packages}"
				return 1
			fi
			;;
		'fedora')
			if ! dnf remove -y --noautoremove $packages; then
				error "Failed to remove packages: ${packages}"
				return 1
			fi
			;;
		'centos'|'almalinux'|'rocky'|'oracle')
			if ! yum remove -y --noautoremove $packages; then
				error "Failed to remove packages: ${packages}"
				return 1
			fi
			;;
		'arch')
			if ! pacman -Rs --noconfirm $packages; then
				error "Failed to remove packages: ${packages}"
				return 1
			fi
			;;
		'alpine')
			if ! apk del $packages; then
				error "Failed to remove packages: ${packages}"
				return 1
			fi
			;;
		*)
			error "Unsupported operating system: ${os}"
			return 1
			;;
	esac
	
	success "Package removal completed successfully for ${os}"
	return 0
}

function installWireGuard() {

	# Run setup questions first
	installQuestions

	# Check if we need to use BoringTun instead of WireGuard kernel module
	if [[ ${LXC_HASWIREGUARD} == false ]]; then
		success "Installing BoringTun instead of WireGuard kernel module..."
	fi

	# Install WireGuard tools and module
	if [[ ${LXC_HASWIREGUARD} == false && ${INSTALL_BORINGTUN} == 'y' ]]; then
		# Install BoringTun instead of WireGuard kernel module
		# Note: We need wireguard-tools for wg-quick script, but not the kernel module
		case ${OS} in
			'ubuntu'|'debian')
				if ! install_packages "${OS}" "curl iptables resolvconf qrencode build-essential pkg-config libssl-dev wireguard-tools" true; then
					error "Failed to install packages for BoringTun on ${OS}"
					exit 1
				fi
				;;
			'fedora')
				if ! install_packages "${OS}" "curl iptables qrencode gcc openssl-devel wireguard-tools" true; then
					error "Failed to install packages for BoringTun on ${OS}"
					exit 1
				fi
				;;
			'centos'|'almalinux'|'rocky')
				if ! install_packages "${OS}" "curl iptables qrencode gcc openssl-devel wireguard-tools" true; then
					error "Failed to install packages for BoringTun on ${OS}"
					exit 1
				fi
				;;
			'oracle')
				if ! install_packages "${OS}" "curl iptables qrencode gcc openssl-devel wireguard-tools" true; then
					error "Failed to install packages for BoringTun on ${OS}"
					exit 1
				fi
				;;
			'arch')
				if ! install_packages "${OS}" "curl qrencode rust wireguard-tools" true; then
					error "Failed to install packages for BoringTun on ${OS}"
					exit 1
				fi
				;;
			'alpine')
				if ! install_packages "${OS}" "curl iptables libqrencode-tools rust cargo wireguard-tools" true; then
					error "Failed to install packages for BoringTun on ${OS}"
					exit 1
				fi
				;;
		esac
		
		success "BoringTun packages installed successfully."
		
		# Configure systemd service for BoringTun
		if [[ ${OS} != 'alpine' ]]; then
			sed -i '19 i Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun-cli' /lib/systemd/system/wg-quick@.service
			sed -i '20 i Environment=WG_SUDO=1' /lib/systemd/system/wg-quick@.service
			systemctl daemon-reload
			echo "Systemd service configured for BoringTun."
		fi
		
		# Set environment variables for BoringTun
		echo "WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun-cli" >> /etc/environment
		echo "WG_SUDO=1" >> /etc/environment
		echo "Environment variables set for BoringTun userspace implementation."
	else
		# Install regular WireGuard
		case ${OS} in
			'ubuntu'|'debian')
				if ! install_packages "${OS}" "wireguard iptables resolvconf qrencode"; then
					error "Failed to install WireGuard packages on ${OS}"
					exit 1
				fi
				;;
			'fedora')
				if ! install_packages "${OS}" "wireguard-tools iptables qrencode"; then
					error "Failed to install WireGuard packages on ${OS}"
					exit 1
				fi
				;;
			'centos'|'almalinux'|'rocky')
				if [[ ${VERSION_ID} == 8* ]]; then
					# CentOS 8 needs EPEL and ELRepo
					info "Installing EPEL and ELRepo for CentOS 8..."
					if ! yum install -y epel-release elrepo-release; then
						error "Failed to install EPEL and ELRepo repositories"
						exit 1
					fi
					if ! yum install -y kmod-wireguard; then
						error "Failed to install WireGuard kernel module"
						exit 1
					fi
					if ! yum install -y qrencode; then
						error "Failed to install qrencode (not available on release 9)"
						exit 1
					fi
				fi
				if ! install_packages "${OS}" "wireguard-tools iptables"; then
					error "Failed to install WireGuard packages on ${OS}"
					exit 1
				fi
				;;
			'oracle')
				# Oracle Linux 8 needs special repository configuration
				info "Configuring Oracle Linux repositories..."
				if ! dnf install -y oraclelinux-developer-release-el8; then
					error "Failed to install Oracle Linux developer release"
					exit 1
				fi
				if ! dnf config-manager --disable -y ol8_developer; then
					error "Failed to disable ol8_developer repository"
					exit 1
				fi
				if ! dnf config-manager --enable -y ol8_developer_UEKR6; then
					error "Failed to enable ol8_developer_UEKR6 repository"
					exit 1
				fi
				if ! dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'; then
					error "Failed to configure repository package inclusion"
					exit 1
				fi
				if ! install_packages "${OS}" "wireguard-tools qrencode iptables"; then
					error "Failed to install WireGuard packages on ${OS}"
					exit 1
				fi
				;;
			'arch')
				if ! install_packages "${OS}" "wireguard-tools qrencode"; then
					error "Failed to install WireGuard packages on ${OS}"
					exit 1
				fi
				;;
			'alpine')
				if ! install_packages "${OS}" "wireguard-tools iptables libqrencode-tools"; then
					error "Failed to install WireGuard packages on ${OS}"
					exit 1
				fi
				;;
		esac
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params

	# Always build address string with both IPv4 and IPv6 to prevent VPN leaks
	ADDRESS_STRING="${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64"

	# Add server interface
	echo "[Interface]
Address = ${ADDRESS_STRING}
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Add MTU setting for BoringTun
	if [[ ${INSTALL_BORINGTUN} == 'y' ]]; then
		echo "MTU = 1420" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		# Use separate interfaces for IPv4 and IPv6 if they exist, otherwise use the primary interface
		IPV4_INTERFACE="${SERVER_NIC_V4:-${SERVER_PUB_NIC}}"
		IPV6_INTERFACE="${SERVER_NIC_V6:-${SERVER_PUB_NIC}}"
		
		# Always build PostUp/PostDown rules for both IPv4 and IPv6 to prevent VPN leaks
		POSTUP_RULES="PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${IPV4_INTERFACE} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${IPV4_INTERFACE} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${IPV6_INTERFACE} -j MASQUERADE"
		
		POSTDOWN_RULES="PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${IPV4_INTERFACE} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${IPV4_INTERFACE} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${IPV6_INTERFACE} -j MASQUERADE"
		
		echo "${POSTUP_RULES}
${POSTDOWN_RULES}" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server based on available IP families
	SYSCTL_RULES=""
	if [[ ${HAS_IPV4} == true ]]; then
		SYSCTL_RULES="net.ipv4.ip_forward = 1"
	fi
	if [[ ${HAS_IPV6} == true ]]; then
		if [[ -n ${SYSCTL_RULES} ]]; then
			SYSCTL_RULES="${SYSCTL_RULES}
net.ipv6.conf.all.forwarding = 1"
		else
			SYSCTL_RULES="net.ipv6.conf.all.forwarding = 1"
		fi
	fi
	echo "${SYSCTL_RULES}" >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system

		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	fi

	newClient

	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status\n\n${NC}"
		else
			echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		fi
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	local ENDPOINT
	local CLIENT_NAME
	local CLIENT_EXISTS
	local DOT_IP
	local DOT_EXISTS
	local BASE_IP
	local IPV4_EXISTS
	local CLIENT_WG_IPV4
	local IPV6_EXISTS
	local CLIENT_WG_IPV6
	local CLIENT_PRIV_KEY
	local CLIENT_PUB_KEY
	local CLIENT_PRE_SHARED_KEY
	local HOME_DIR

	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		highlight "The subnet configured supports only 253 clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

# Uncomment the next line to set a custom MTU
# This might impact performance, so use it only if you know what you are doing
# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU
# MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	local NUMBER_OF_CLIENTS

	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	local NUMBER_OF_CLIENTS
	local CLIENT_NUMBER
	local CLIENT_NAME
	local HOME_DIR

	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	local REMOVE
	local WG_RUNNING

	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop
			rc-update del "wg-quick.${SERVER_WG_NIC}"
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			rc-update del sysctl
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}"
			systemctl disable "wg-quick@${SERVER_WG_NIC}"
		fi

		case ${OS} in
			'ubuntu'|'debian')
				remove_packages "${OS}" "wireguard wireguard-tools qrencode"
				;;
			'fedora')
				remove_packages "${OS}" "wireguard-tools qrencode"
				;;
			'centos'|'almalinux'|'rocky')
				remove_packages "${OS}" "wireguard-tools"
				if [[ ${VERSION_ID} == 8* ]]; then
					yum remove --noautoremove kmod-wireguard qrencode
				fi
				;;
			'oracle')
				remove_packages "${OS}" "wireguard-tools qrencode"
				;;
			'arch')
				remove_packages "${OS}" "wireguard-tools qrencode"
				;;
			'alpine')
				# Alpine has special qrencode handling
				(cd qrencode-4.1.1 || exit && make uninstall)
				rm -rf qrencode-* || exit
				remove_packages "${OS}" "wireguard-tools libqrencode libqrencode-tools"
				;;
		esac

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			# Reload sysctl
			sysctl --system

			# Check if WireGuard is running
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		fi
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			exit 1
		else
			echo "WireGuard uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	local MENU_OPTION

	success "Welcome to WireGuard-install!"
	info "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	warning "It looks like WireGuard is already installed."
	echo ""
	info "What do you want to do?"
	info "   1) Add a new user"
	info "   2) List all users"
	info "   3) Revoke existing user"
	info "   4) Uninstall WireGuard"
	info "   5) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallWg
		;;
	5)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
else
	installWireGuard
fi
while true; do
	manageMenu
done