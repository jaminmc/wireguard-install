#!/bin/bash

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

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
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		echo ""
		read -rp "Do you want to continue anyway? [y/n]: " -e CONTINUE_LXC
		CONTINUE_LXC=${CONTINUE_LXC:-n}
		if [[ $CONTINUE_LXC != 'y' && $CONTINUE_LXC != 'Y' ]]; then
			exit 1
		fi
		echo "Continuing with LXC environment..."
		
		# Check if WireGuard kernel module is available
		if lsmod | grep -q wireguard; then
			echo "WireGuard kernel module is loaded and available."
			LXC_HASWIREGUARD=true
		elif [ -e "/sys/module/wireguard" ]; then
			echo "WireGuard kernel module is available (built into kernel)."
			LXC_HASWIREGUARD=true
		elif [ -e "/lib/modules/$(uname -r)/kernel/net/wireguard/wireguard.ko" ] || [ -e "/lib/modules/$(uname -r)/kernel/net/wireguard/wireguard.ko.xz" ]; then
			echo "WireGuard kernel module is available on disk."
			LXC_HASWIREGUARD=true
		else
			echo "Warning: WireGuard kernel module is not available in this LXC container."
			echo "The kernel module must be installed on the host system."
			LXC_HASWIREGUARD=false
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
        ["10.0.0.0/8"]="167772160 184549375"           # RFC 1918
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

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
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
	checkVirt
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
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
			echo "Detected non-routable IPv4 address: ${SERVER_PUB_IP_V4}"
			HAS_IPV4=true  # Still has IPv4, just not routable
			HAS_ROUTABLE_IPV4=false
		else
			echo "Detected public IPv4 address: ${SERVER_PUB_IP_V4}"
			HAS_IPV4=true
			HAS_ROUTABLE_IPV4=true
		fi
	fi
	
	# Check if IPv6 is available
	if [[ -n ${SERVER_PUB_IP_V6} ]]; then
		echo "Detected IPv6 address: ${SERVER_PUB_IP_V6}"
		HAS_IPV6=true
	fi
	
	# Determine which IP to use as default
	if [[ ${HAS_ROUTABLE_IPV4} == true && ${HAS_IPV6} == true ]]; then
		# Both available, prefer IPv4 for better compatibility
		SERVER_PUB_IP="${SERVER_PUB_IP_V4}"
		IP_FAMILY="ipv4"
		echo "Using public IPv4 as default (IPv6 also available)"
	elif [[ ${HAS_ROUTABLE_IPV4} == true ]]; then
		# Only routable IPv4 available
		SERVER_PUB_IP="${SERVER_PUB_IP_V4}"
		IP_FAMILY="ipv4"
		echo "Using public IPv4 as default"
	elif [[ ${HAS_IPV6} == true ]]; then
		# Only IPv6 available or IPv4 is non-routable
		SERVER_PUB_IP="${SERVER_PUB_IP_V6}"
		IP_FAMILY="ipv6"
		if [[ -n ${SERVER_PUB_IP_V4} ]]; then
			echo "IPv4 is non-routable, using IPv6 as default"
		else
			echo "Using IPv6 as default"
		fi
	else
		# No public IPs detected
		echo "No public IPv4 or IPv6 addresses detected"
		echo "You may need to manually specify your public IP address"
		SERVER_PUB_IP=""
		IP_FAMILY=""
	fi
	if [[ -z ${SERVER_PUB_IP} ]]; then
		echo ""
		echo "No public IP address was automatically detected."
		echo "This might happen if:"
		echo "  - You're behind NAT"
		echo "  - You're in a private network"
		echo "  - Your server uses a different network configuration"
		echo ""
		echo "Please enter your server's public IP address manually."
		echo "You can find it by visiting: https://whatismyipaddress.com/"
	fi
	echo ""
	until is_valid_ip "${SERVER_PUB_IP}"; do
		read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP
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

	# Only prompt for IPv4 if the server has IPv4
	if [[ ${HAS_IPV4} == true ]]; then
		until is_valid_ip "${SERVER_WG_IPV4}" && [[ ${SERVER_WG_IPV4} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; do
			read -rp "Server WireGuard IPv4: " -e -i "${DEFAULT_IPV4}" SERVER_WG_IPV4
		done
	else
		SERVER_WG_IPV4=""
	fi

	# Only prompt for IPv6 if the server has IPv6
	if [[ ${HAS_IPV6} == true ]]; then
		until is_valid_ip "${SERVER_WG_IPV6}" && [[ ${SERVER_WG_IPV6} =~ .*:.* ]]; do
			read -rp "Server WireGuard IPv6: " -e -i "${DEFAULT_IPV6}" SERVER_WG_IPV6
		done
	else
		SERVER_WG_IPV6=""
	fi

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Detect system DNS servers
	SYSTEM_DNS=$(get_system_dns)
	SYSTEM_DNS_1=$(echo "$SYSTEM_DNS" | awk '{print $1}')
	SYSTEM_DNS_2=$(echo "$SYSTEM_DNS" | awk '{print $2}')
	
	# Set DNS defaults based on available IP families and system DNS
	if [[ ${HAS_IPV4} == true ]]; then
		# Use system DNS if valid, otherwise fallback to Cloudflare
		if [[ -n "$SYSTEM_DNS_1" ]] && is_valid_ip "$SYSTEM_DNS_1"; then
			DEFAULT_DNS_1="$SYSTEM_DNS_1"
		else
			DEFAULT_DNS_1="1.1.1.1"
		fi
		if [[ -n "$SYSTEM_DNS_2" ]] && is_valid_ip "$SYSTEM_DNS_2"; then
			DEFAULT_DNS_2="$SYSTEM_DNS_2"
		else
			DEFAULT_DNS_2="1.0.0.1"
		fi
	else
		# IPv6-only DNS servers
		if [[ -n "$SYSTEM_DNS_1" ]] && is_valid_ip "$SYSTEM_DNS_1" && [[ "$SYSTEM_DNS_1" =~ .*:.* ]]; then
			DEFAULT_DNS_1="$SYSTEM_DNS_1"
		else
			DEFAULT_DNS_1="2606:4700:4700::1111"
		fi
		if [[ -n "$SYSTEM_DNS_2" ]] && is_valid_ip "$SYSTEM_DNS_2" && [[ "$SYSTEM_DNS_2" =~ .*:.* ]]; then
			DEFAULT_DNS_2="$SYSTEM_DNS_2"
		else
			DEFAULT_DNS_2="2606:4700:4700::1001"
		fi
	fi
	
	# Show detected system DNS servers
	if [[ -n "$SYSTEM_DNS_1" ]] && is_valid_ip "$SYSTEM_DNS_1"; then
		echo "Detected system DNS servers: $SYSTEM_DNS_1${SYSTEM_DNS_2:+ and $SYSTEM_DNS_2}"
	else
		echo "Using fallback DNS servers: $DEFAULT_DNS_1${DEFAULT_DNS_2:+ and $DEFAULT_DNS_2}"
	fi
	
	# DNS configuration
	until is_valid_ip "${CLIENT_DNS_1}"; do
		read -rp "First DNS resolver to use for the clients: " -e -i "${DEFAULT_DNS_1}" CLIENT_DNS_1
	done
	until is_valid_ip "${CLIENT_DNS_2}"; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i "${DEFAULT_DNS_2}" CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	# Set default ALLOWED_IPS based on available IP families
	if [[ ${HAS_IPV4} == true && ${HAS_IPV6} == true ]]; then
		DEFAULT_ALLOWED_IPS="0.0.0.0/0,::/0"
	elif [[ ${HAS_IPV4} == true ]]; then
		DEFAULT_ALLOWED_IPS="0.0.0.0/0"
	else
		DEFAULT_ALLOWED_IPS="::/0"
	fi
	
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

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Check if we need to use BoringTun instead of WireGuard kernel module
	if [[ ${LXC_HASWIREGUARD} == false ]]; then
		echo ""
		echo "WireGuard kernel module is not available in this LXC container."
		echo "You can install BoringTun (userspace WireGuard implementation) instead."
		echo ""
		read -rp "Do you want to install BoringTun? [y/n]: " -e INSTALL_BORINGTUN
		INSTALL_BORINGTUN=${INSTALL_BORINGTUN:-n}
		if [[ $INSTALL_BORINGTUN != 'y' && $INSTALL_BORINGTUN != 'Y' ]]; then
			echo "WireGuard kernel module is required. Exiting..."
			exit 1
		fi
		echo "Installing BoringTun instead of WireGuard kernel module..."
	fi

	# Install WireGuard tools and module
	if [[ ${LXC_HASWIREGUARD} == false && ${INSTALL_BORINGTUN} == 'y' ]]; then
		# Install BoringTun instead of WireGuard kernel module
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get update
			apt-get install -y curl iptables resolvconf qrencode build-essential pkg-config libssl-dev wireguard-tools
			# Install Rust and Cargo
			curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
			source ~/.cargo/env
			# Install BoringTun via Cargo
			cargo install boringtun-cli
			# Create symlink for wg command
			ln -sf ~/.cargo/bin/boringtun /usr/local/bin/wg
		elif [[ ${OS} == 'fedora' ]]; then
			dnf install -y curl iptables qrencode gcc openssl-devel wireguard-tools
			# Install Rust and Cargo
			curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
			source ~/.cargo/env
			# Install BoringTun via Cargo
			cargo install boringtun-cli
			# Create symlink for wg command
			ln -sf ~/.cargo/bin/boringtun /usr/local/bin/wg
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum install -y curl iptables gcc openssl-devel wireguard-tools
			# Install Rust and Cargo
			curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
			source ~/.cargo/env
			# Install BoringTun via Cargo
			cargo install boringtun-cli
			# Create symlink for wg command
			ln -sf ~/.cargo/bin/boringtun /usr/local/bin/wg
		elif [[ ${OS} == 'arch' ]]; then
			pacman -S --needed --noconfirm curl qrencode rust wireguard-tools
			# Install BoringTun via Cargo
			cargo install boringtun-cli
			# Create symlink for wg command
			ln -sf ~/.cargo/bin/boringtun /usr/local/bin/wg
		elif [[ ${OS} == 'alpine' ]]; then
			apk update
			apk add curl iptables libqrencode-tools rust cargo wireguard-tools
			# Install BoringTun via Cargo
			cargo install boringtun-cli
			# Create symlink for wg command
			ln -sf ~/.cargo/bin/boringtun /usr/local/bin/wg
		fi
		echo "BoringTun installed successfully."
		
		# Set environment variables for BoringTun
		echo "WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun-cli" >> /etc/environment
		echo "WG_SUDO=1" >> /etc/environment
		echo "Environment variables set for BoringTun userspace implementation."
	else
		# Install regular WireGuard
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
			apt-get update
			apt-get install -y wireguard iptables resolvconf qrencode
		elif [[ ${OS} == 'debian' && ${VERSION_ID} == 10 ]]; then
			if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
				echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
				apt-get update
			fi
			apt update
			apt-get install -y iptables resolvconf qrencode
			apt-get install -y -t buster-backports wireguard
		elif [[ ${OS} == 'debian' ]]; then
			apt-get update
			apt-get install -y wireguard iptables resolvconf qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf install -y dnf-plugins-core
				dnf copr enable -y jdoss/wireguard
				dnf install -y wireguard-dkms
			fi
			dnf install -y wireguard-tools iptables qrencode
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			if [[ ${VERSION_ID} == 8* ]]; then
				yum install -y epel-release elrepo-release
				yum install -y kmod-wireguard
				yum install -y qrencode # not available on release 9
			fi
			yum install -y wireguard-tools iptables
		elif [[ ${OS} == 'oracle' ]]; then
			dnf install -y oraclelinux-developer-release-el8
			dnf config-manager --disable -y ol8_developer
			dnf config-manager --enable -y ol8_developer_UEKR6
			dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
			dnf install -y wireguard-tools qrencode iptables
		elif [[ ${OS} == 'arch' ]]; then
			pacman -S --needed --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'alpine' ]]; then
			apk update
			apk add wireguard-tools iptables libqrencode-tools
		fi
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

	# Build address string based on available IP families
	ADDRESS_STRING=""
	if [[ ${HAS_IPV4} == true ]]; then
		ADDRESS_STRING="${SERVER_WG_IPV4}/24"
	fi
	if [[ ${HAS_IPV6} == true ]]; then
		if [[ -n ${ADDRESS_STRING} ]]; then
			ADDRESS_STRING="${ADDRESS_STRING},${SERVER_WG_IPV6}/64"
		else
			ADDRESS_STRING="${SERVER_WG_IPV6}/64"
		fi
	fi

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
		
		# Build PostUp/PostDown rules based on available IP families
		POSTUP_RULES="PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT"
		POSTDOWN_RULES="PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT"
		
		if [[ ${HAS_IPV4} == true ]]; then
			POSTUP_RULES="${POSTUP_RULES}
PostUp = iptables -I FORWARD -i ${IPV4_INTERFACE} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${IPV4_INTERFACE} -j MASQUERADE"
			POSTDOWN_RULES="${POSTDOWN_RULES}
PostDown = iptables -D FORWARD -i ${IPV4_INTERFACE} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${IPV4_INTERFACE} -j MASQUERADE"
		fi
		
		if [[ ${HAS_IPV6} == true ]]; then
			POSTUP_RULES="${POSTUP_RULES}
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${IPV6_INTERFACE} -j MASQUERADE"
			POSTDOWN_RULES="${POSTDOWN_RULES}
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${IPV6_INTERFACE} -j MASQUERADE"
		fi
		
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
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

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
		echo "The subnet configured supports only 253 clients."
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
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
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

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 || exit && make uninstall)
			rm -rf qrencode-* || exit
			apk del wireguard-tools libqrencode libqrencode-tools
		fi

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
	echo "Welcome to WireGuard-install!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "It looks like WireGuard is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Uninstall WireGuard"
	echo "   5) Exit"
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
	manageMenu
else
	installWireGuard
fi
