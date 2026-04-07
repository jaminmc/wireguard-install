#!/bin/bash

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function installPackages() {
	if ! "$@"; then
		echo -e "${RED}Failed to install packages.${NC}"
		echo "Please check your internet connection and package sources."
		exit 1
	fi
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	Container=0
	if command -v virt-what &>/dev/null; then
		VIRT=$(virt-what)
	else
		VIRT=$(systemd-detect-virt)
	fi
	if [[ ${VIRT} == "openvz" ]]; then
		if ip link add wg999 type wireguard 2>/dev/null; then
			echo "OpenVZ is not supported, but it seems to have correct kernel modules."
			ip link del wg999
			read -rp "Press enter to continue at your own risk, or CTRL-C to quit."
			Container=1
		else
			echo "OpenVZ is not supported with kernel modules inside the container."
			echo "Continuing in container mode and will use userspace AmneziaWG (amneziawg-go)."
			read -rp "Press enter to continue at your own risk, or CTRL-C to quit."
			Container=1
		fi
	fi
	if [[ ${VIRT} == "lxc" ]]; then
		if ip link add wg999 type wireguard 2>/dev/null; then
			ip link del wg999
			echo "LXC is currently in Beta."
			echo "WireGuard can technically run in an LXC container,"
			echo "but the kernel module has to be installed on the host,"
			echo "the container has to be run with some specific parameters"
			echo "and only the tools need to be installed in the container."
			echo "The kernel seems to support WireGuard."
			read -rp "Press enter to continue at your own risk, or CTRL-C to quit."
			Container=1
		else
			echo "Your LXC environment does not have the WireGuard kernel module available."
			echo "Continuing in container mode and will use userspace AmneziaWG (amneziawg-go)."
			read -rp "Press enter to continue at your own risk, or CTRL-C to quit."
			Container=1
		fi
	fi
}

function installAmneziaWGGo() {
	# Build/install amneziawg-go in a portable way
	# (preferred over downloading binaries so it works on all supported distros)
	if command -v amneziawg-go &>/dev/null; then
		return 0
	fi

	if ! command -v go &>/dev/null; then
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get update
			installPackages apt-get install -y --no-install-recommends golang
		elif [[ ${OS} == 'fedora' ]]; then
			installPackages dnf install -y golang
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
			installPackages yum install -y golang || installPackages dnf install -y golang
		elif [[ ${OS} == 'arch' ]]; then
			installPackages pacman -S --needed --noconfirm go
		elif [[ ${OS} == 'alpine' ]]; then
			apk update
			installPackages apk add go
		fi
	fi

	if ! command -v go &>/dev/null; then
		echo -e "${RED}Failed to install Go toolchain required for amneziawg-go.${NC}"
		exit 1
	fi

	# Install the latest amneziawg-go (userspace implementation)
	# Repo: https://github.com/amnezia-vpn/amneziawg-go
	installPackages env GOBIN=/usr/local/bin GO111MODULE=on go install github.com/amnezia-vpn/amneziawg-go@latest

	if ! command -v amneziawg-go &>/dev/null; then
		echo -e "${RED}amneziawg-go installation failed. The 'amneziawg-go' command was not found.${NC}"
		exit 1
	fi
}

function installAmneziaWGKernel() {
	# Best-effort DKMS install for bare metal/VMs.
	# Package availability depends on distro/repositories.
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
		apt-get update
		installPackages apt-get install -y iptables resolvconf qrencode
		installPackages apt-get install -y amneziawg-dkms amneziawg-tools
	elif [[ ${OS} == 'fedora' ]]; then
		installPackages dnf install -y amneziawg-dkms amneziawg-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
		installPackages yum install -y amneziawg-dkms amneziawg-tools iptables qrencode || true
		installPackages dnf install -y amneziawg-dkms amneziawg-tools iptables qrencode || true
	elif [[ ${OS} == 'arch' ]]; then
		installPackages pacman -S --needed --noconfirm amneziawg-dkms amneziawg-tools iptables qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		installPackages apk add amneziawg-tools iptables libqrencode-tools
	fi
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
			if ! (apk update && apk add virt-what); then
				echo -e "${RED}Failed to install virt-what. Continuing without virtualization check.${NC}"
			fi
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

function detectIPStack() {
	# Detect whether the server has usable IPv4 and/or IPv6 connectivity.
	# We treat a family as "available" if there is either a default route or a global address.
	#
	# This is intentionally conservative: it avoids generating config/rules for families that
	# clearly don't exist (e.g., IPv6-only servers, IPv4-only networks).
	IPV4_AVAILABLE=0
	IPV6_AVAILABLE=0
	CLAT_PRESENT=0

	if ip -4 route ls default 2>/dev/null | grep -q '^default'; then
		IPV4_AVAILABLE=1
	elif ip -4 addr show scope global 2>/dev/null | grep -q ' inet '; then
		IPV4_AVAILABLE=1
	fi

	if ip -6 route ls default 2>/dev/null | grep -q '^default'; then
		IPV6_AVAILABLE=1
	elif ip -6 addr show scope global 2>/dev/null | grep -q ' inet6 '; then
		IPV6_AVAILABLE=1
	fi

	# 464XLAT/CLAT: on IPv6-only hosts, IPv4 functionality can be provided via a clat* interface.
	# In that scenario, we still want to generate dual-stack tunnel addressing by default.
	if ip link show 2>/dev/null | grep -qE '^[0-9]+: clat'; then
		CLAT_PRESENT=1
		if [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
			IPV4_AVAILABLE=1
		fi
	fi
}

function generateRandomTunnelPrefix() {
	# Generate two random octets (0-254) used to derive matching IPv4/IPv6 defaults
	# Example: 10.<A>.<B>.1 and fd42:<A>:<B>::1
	TUN_OCTET_A=$(shuf -i0-254 -n1)
	TUN_OCTET_B=$(shuf -i0-254 -n1)
}

function isValidIPv4() {
	local IP=$1
	[[ ${IP} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]
}

function isValidIPv6() {
	local IP=$1
	# Basic sanity check for IPv6 literals (full validation is intentionally avoided in bash)
	[[ ${IP} =~ : ]] && [[ ${IP} =~ ^[0-9a-fA-F:]+$ ]]
}

function isValidIP() {
	local IP=$1
	isValidIPv4 "${IP}" || isValidIPv6 "${IP}"
}

function getHostDNSResolvers() {
	# Returns up to two DNS resolvers (space-separated), if detected.
	# Handles systemd-resolved stub (/etc/resolv.conf -> 127.0.0.53) by reading the "real" file.
	local RESOLV_FILE="/etc/resolv.conf"
	local NS

	if [[ -r ${RESOLV_FILE} ]] && grep -qE '^\s*nameserver\s+127\.0\.0\.53\s*$' "${RESOLV_FILE}"; then
		if [[ -r /run/systemd/resolve/resolv.conf ]]; then
			RESOLV_FILE="/run/systemd/resolve/resolv.conf"
		elif [[ -r /run/systemd/resolve/resolv.conf ]]; then
			RESOLV_FILE="/run/systemd/resolve/resolv.conf"
		fi
	fi

	NS=$(awk '/^[[:space:]]*nameserver[[:space:]]+/ {print $2}' "${RESOLV_FILE}" 2>/dev/null \
		| grep -Ev '^(127\.|::1$|0\.0\.0\.0$)$' \
		| awk '!seen[$0]++' \
		| head -n 2 | tr '\n' ' ')

	echo "${NS}"
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	detectIPStack
	generateRandomTunnelPrefix
	if [[ ${IPV4_AVAILABLE} -eq 0 && ${IPV6_AVAILABLE} -eq 0 ]]; then
		echo -e "${RED}No IPv4 or IPv6 connectivity detected.${NC}"
		echo "This installer requires at least one IP family to be available on the server."
		exit 1
	fi

	# Detect default route interfaces (IPv4 and IPv6 can differ)
	SERVER_NIC4="$(ip -4 route ls default 2>/dev/null | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	SERVER_NIC6="$(ip -6 route ls default 2>/dev/null | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"

	# Detect public IP address and pre-fill for the user.
	#
	# If IPv4's default route goes through a 464XLAT interface (clat*), prefer IPv6
	# as the server is typically IPv6-only and CLAT provides IPv4 functionality.
	if [[ ${IPV6_AVAILABLE} -eq 1 && -n ${SERVER_NIC4} && ${SERVER_NIC4} == clat* ]]; then
		SERVER_PUB_IP="$(ip -6 addr show ${SERVER_NIC6:+dev "${SERVER_NIC6}"} scope global 2>/dev/null | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
		if [[ -z ${SERVER_PUB_IP} ]]; then
			SERVER_PUB_IP="$(ip -6 addr show scope global 2>/dev/null | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
		fi
	else
		if [[ ${IPV4_AVAILABLE} -eq 1 ]]; then
			SERVER_PUB_IP="$(ip -4 addr show ${SERVER_NIC4:+dev "${SERVER_NIC4}"} scope global 2>/dev/null | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
		fi
		if [[ -z ${SERVER_PUB_IP} && ${IPV6_AVAILABLE} -eq 1 ]]; then
			SERVER_PUB_IP="$(ip -6 addr show ${SERVER_NIC6:+dev "${SERVER_NIC6}"} scope global 2>/dev/null | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
		fi
	fi
	read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Backwards-compatible single NIC var used across the script
	# plus separate NICs used for v4/v6-specific firewall rules.
	if [[ ${IPV4_AVAILABLE} -eq 1 && ${IPV6_AVAILABLE} -eq 1 && -n ${SERVER_NIC4} && -n ${SERVER_NIC6} && ${SERVER_NIC4} != "${SERVER_NIC6}" ]]; then
		until [[ ${SERVER_PUB_NIC4} =~ ^[a-zA-Z0-9_]+$ ]]; do
			read -rp "Public interface for IPv4 (default route): " -e -i "${SERVER_NIC4}" SERVER_PUB_NIC4
		done
		until [[ ${SERVER_PUB_NIC6} =~ ^[a-zA-Z0-9_]+$ ]]; do
			read -rp "Public interface for IPv6 (default route): " -e -i "${SERVER_NIC6}" SERVER_PUB_NIC6
		done
		# Keep legacy variable populated for other uses.
		# On IPv6-only + 464XLAT (clat*), prefer the IPv6 egress interface as "public".
		if [[ -n ${SERVER_NIC4} && ${SERVER_NIC4} == clat* ]]; then
			SERVER_PUB_NIC=${SERVER_PUB_NIC6}
		else
			SERVER_PUB_NIC=${SERVER_PUB_NIC4}
		fi
	else
		SERVER_NIC="${SERVER_NIC4:-${SERVER_NIC6}}"
		until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
			read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
		done
		if [[ ${IPV4_AVAILABLE} -eq 1 ]]; then
			SERVER_PUB_NIC4=${SERVER_PUB_NIC}
		fi
		if [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
			SERVER_PUB_NIC6=${SERVER_PUB_NIC}
		fi
	fi

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
	done

	if [[ ${IPV4_AVAILABLE} -eq 1 ]]; then
		RAND_WG_IPV4_DEFAULT="10.${TUN_OCTET_A}.${TUN_OCTET_B}.1"
		until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
			read -rp "Server WireGuard IPv4: " -e -i "${RAND_WG_IPV4_DEFAULT}" SERVER_WG_IPV4
		done
	else
		SERVER_WG_IPV4=""
	fi

	if [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
		RAND_WG_IPV6_DEFAULT="fd42:${TUN_OCTET_A}:${TUN_OCTET_B}::1"
		until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
			read -rp "Server WireGuard IPv6: " -e -i "${RAND_WG_IPV6_DEFAULT}" SERVER_WG_IPV6
		done
	else
		SERVER_WG_IPV6=""
	fi

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# DNS selection (host DNS, curated public DNS, or custom). Supports IPv4 and IPv6.
	HOST_DNS="$(getHostDNSResolvers)"
	HOST_DNS_1=$(echo "${HOST_DNS}" | awk '{print $1}')
	HOST_DNS_2=$(echo "${HOST_DNS}" | awk '{print $2}')

	echo ""
	echo "DNS resolvers to use for the clients:"
	if [[ -n ${HOST_DNS_1} ]]; then
		echo "   1) Use host resolvers (${HOST_DNS_1}${HOST_DNS_2:+, ${HOST_DNS_2}})"
	else
		echo "   1) Use host resolvers (not detected)"
	fi
	echo "   2) Cloudflare (1.1.1.1, 1.0.0.1) + IPv6 (2606:4700:4700::1111, 2606:4700:4700::1001)"
	echo "   3) Google (8.8.8.8, 8.8.4.4) + IPv6 (2001:4860:4860::8888, 2001:4860:4860::8844)"
	echo "   4) Quad9 (9.9.9.9, 149.112.112.112) + IPv6 (2620:fe::fe, 2620:fe::9)"
	echo "   5) AdGuard (94.140.14.14, 94.140.15.15) + IPv6 (2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff)"
	echo "   6) Custom (enter your own)"

	# Default to host resolvers if detected; otherwise Cloudflare.
	if [[ -n ${HOST_DNS_1} ]]; then
		DNS_MENU_DEFAULT=1
	else
		DNS_MENU_DEFAULT=2
	fi
	until [[ ${DNS_MENU} =~ ^[1-6]$ ]]; do
		read -rp "Select an option [${DNS_MENU_DEFAULT}]: " DNS_MENU
		DNS_MENU=${DNS_MENU:-${DNS_MENU_DEFAULT}}
	done

	case "${DNS_MENU}" in
	1)
		CLIENT_DNS_1=${HOST_DNS_1}
		CLIENT_DNS_2=${HOST_DNS_2:-${HOST_DNS_1}}
		;;
	2)
		if [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
			CLIENT_DNS_1="2606:4700:4700::1111"
			CLIENT_DNS_2="2606:4700:4700::1001"
		else
			CLIENT_DNS_1="1.1.1.1"
			CLIENT_DNS_2="1.0.0.1"
		fi
		;;
	3)
		if [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
			CLIENT_DNS_1="2001:4860:4860::8888"
			CLIENT_DNS_2="2001:4860:4860::8844"
		else
			CLIENT_DNS_1="8.8.8.8"
			CLIENT_DNS_2="8.8.4.4"
		fi
		;;
	4)
		if [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
			CLIENT_DNS_1="2620:fe::fe"
			CLIENT_DNS_2="2620:fe::9"
		else
			CLIENT_DNS_1="9.9.9.9"
			CLIENT_DNS_2="149.112.112.112"
		fi
		;;
	5)
		if [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
			CLIENT_DNS_1="2a10:50c0::ad1:ff"
			CLIENT_DNS_2="2a10:50c0::ad2:ff"
		else
			CLIENT_DNS_1="94.140.14.14"
			CLIENT_DNS_2="94.140.15.15"
		fi
		;;
	6)
		until isValidIP "${CLIENT_DNS_1}"; do
			read -rp "First DNS resolver to use for the clients: " -e -i "${HOST_DNS_1:-1.1.1.1}" CLIENT_DNS_1
		done
		until [[ -z ${CLIENT_DNS_2} ]] || isValidIP "${CLIENT_DNS_2}"; do
			read -rp "Second DNS resolver to use for the clients (optional): " -e -i "${HOST_DNS_2:-}" CLIENT_DNS_2
		done
		if [[ -z ${CLIENT_DNS_2} ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
		;;
	esac

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
		# Default behavior:
		# - Dual-stack servers: full-tunnel both IPv4 + IPv6 (no extra menu)
		# - Single-stack servers: ask whether to full-tunnel (default) or only route the VPN subnet
		if [[ ${IPV4_AVAILABLE} -eq 1 && ${IPV6_AVAILABLE} -eq 1 ]]; then
			CLIENT_ROUTE_IPV4=1
			CLIENT_ROUTE_IPV6=1
			DEFAULT_ALLOWED_IPS='0.0.0.0/0,::/0'
		elif [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
			CLIENT_ROUTE_IPV4=0
			CLIENT_ROUTE_IPV6=1
			read -rp "Route all IPv6 traffic through the VPN? [Y/n]: " -e CLIENT_FULL_TUNNEL
			CLIENT_FULL_TUNNEL=${CLIENT_FULL_TUNNEL:-Y}
			if [[ ${CLIENT_FULL_TUNNEL} =~ ^[Nn]$ ]]; then
				DEFAULT_ALLOWED_IPS="${SERVER_WG_IPV6}/64"
			else
				DEFAULT_ALLOWED_IPS='::/0'
			fi
		else
			CLIENT_ROUTE_IPV4=1
			CLIENT_ROUTE_IPV6=0
			read -rp "Route all IPv4 traffic through the VPN? [Y/n]: " -e CLIENT_FULL_TUNNEL
			CLIENT_FULL_TUNNEL=${CLIENT_FULL_TUNNEL:-Y}
			if [[ ${CLIENT_FULL_TUNNEL} =~ ^[Nn]$ ]]; then
				DEFAULT_ALLOWED_IPS="$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3).0/24"
			else
				DEFAULT_ALLOWED_IPS='0.0.0.0/0'
			fi
		fi
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

	# Install AmneziaWG (preferred) / tools
	#
	# - Bare metal / VM: install kernel module via DKMS (amneziawg-dkms) + tools
	# - Container: install userspace amneziawg-go + wireguard-tools (wg/wg-quick)
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		installPackages apt-get install -y iptables resolvconf qrencode
		if [[ ${Container} == 1 ]]; then
			# Prefer amneziawg-tools if available (UAPI path differs from WireGuard-Go)
			if ! apt-get install -y --no-install-recommends amneziawg-tools; then
				installPackages apt-get install -y --no-install-recommends wireguard-tools
			fi
			installAmneziaWGGo
		else
			installAmneziaWGKernel
		fi
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt-get update
		installPackages apt-get install -y iptables resolvconf qrencode
		if [[ ${Container} == 1 ]]; then
			if ! apt-get install -y -t buster-backports --no-install-recommends amneziawg-tools; then
				installPackages apt-get install -y -t buster-backports --no-install-recommends wireguard-tools
			fi
			installAmneziaWGGo
		else
			installAmneziaWGKernel
		fi
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${Container} == 1 ]]; then
			installPackages dnf install -y wireguard-tools iptables qrencode || true
			installPackages dnf install -y amneziawg-tools || true
			installAmneziaWGGo
		else
			installAmneziaWGKernel
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${Container} == 1 ]]; then
			installPackages yum install -y wireguard-tools iptables || true
			installPackages dnf install -y wireguard-tools iptables || true
			installPackages yum install -y amneziawg-tools || true
			installPackages dnf install -y amneziawg-tools || true
			installPackages yum install -y qrencode || true
			installPackages dnf install -y qrencode || true
			installAmneziaWGGo
		else
			installAmneziaWGKernel
		fi
	elif [[ ${OS} == 'oracle' ]]; then
		if [[ ${Container} == 1 ]]; then
			installPackages dnf install -y wireguard-tools qrencode iptables || true
			installPackages dnf install -y amneziawg-tools || true
			installAmneziaWGGo
		else
			installAmneziaWGKernel
		fi
	elif [[ ${OS} == 'arch' ]]; then
		if [[ ${Container} == 1 ]]; then
			installPackages pacman -S --needed --noconfirm wireguard-tools qrencode
			installPackages pacman -S --needed --noconfirm amneziawg-tools || true
			installAmneziaWGGo
		else
			installAmneziaWGKernel
		fi
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		installPackages apk add wireguard-tools iptables libqrencode-tools
		if [[ ${Container} == 1 ]]; then
			installPackages apk add amneziawg-tools || true
			installAmneziaWGGo
		else
			installAmneziaWGKernel
		fi
	fi

	# Verify installation
	if ! command -v wg &>/dev/null; then
		echo -e "${RED}Installation failed. The 'wg' command was not found.${NC}"
		echo "Please check the installation output above for errors."
		exit 1
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	# When running userspace AmneziaWG, ensure wg-quick uses it.
	if [[ ${Container} == 1 ]] && command -v amneziawg-go &>/dev/null; then
		export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
	fi

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_PUB_NIC4=${SERVER_PUB_NIC4}
SERVER_PUB_NIC6=${SERVER_PUB_NIC6}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
IPV4_AVAILABLE=${IPV4_AVAILABLE}
IPV6_AVAILABLE=${IPV6_AVAILABLE}
CLAT_PRESENT=${CLAT_PRESENT}
CLIENT_ROUTE_IPV4=${CLIENT_ROUTE_IPV4}
CLIENT_ROUTE_IPV6=${CLIENT_ROUTE_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params

	# Add server interface
	{
		echo "[Interface]"
		if [[ -n ${SERVER_WG_IPV4} ]]; then
			echo "Address = ${SERVER_WG_IPV4}/24"
		fi
		if [[ -n ${SERVER_WG_IPV6} ]]; then
			echo "Address = ${SERVER_WG_IPV6}/64"
		fi
		echo "ListenPort = ${SERVER_PORT}"
		echo "PrivateKey = ${SERVER_PRIV_KEY}"
	} >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_RULES="PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp"
		FIREWALLD_RULES_DOWN="PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp"
		if [[ -n ${SERVER_WG_IPV4} ]]; then
			FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
			FIREWALLD_RULES="${FIREWALLD_RULES} && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'"
			FIREWALLD_RULES_DOWN="${FIREWALLD_RULES_DOWN} && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'"
		fi
		if [[ -n ${SERVER_WG_IPV6} ]]; then
			FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
			FIREWALLD_RULES="${FIREWALLD_RULES} && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'"
			FIREWALLD_RULES_DOWN="${FIREWALLD_RULES_DOWN} && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'"
		fi
		echo "${FIREWALLD_RULES}
${FIREWALLD_RULES_DOWN}" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		{
			if [[ -n ${SERVER_WG_IPV4} ]]; then
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT"
				echo "PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC4} -o ${SERVER_WG_NIC} -j ACCEPT"
				echo "PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT"
				echo "PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC4} -j MASQUERADE"
				echo "PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT"
				echo "PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC4} -o ${SERVER_WG_NIC} -j ACCEPT"
				echo "PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT"
				echo "PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC4} -j MASQUERADE"
			fi
			if [[ -n ${SERVER_WG_IPV6} ]]; then
				echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT"
				echo "PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC6} -j MASQUERADE"
				echo "PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT"
				echo "PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC6} -j MASQUERADE"
			fi
		} >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
	{
		if [[ -n ${SERVER_WG_IPV4} ]]; then
			echo "net.ipv4.ip_forward = 1"
		fi
		if [[ -n ${SERVER_WG_IPV6} ]]; then
			echo "net.ipv6.conf.all.forwarding = 1"
		fi
	} >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'fedora' ]]; then
		chmod -v 700 /etc/wireguard
		chmod -v 600 /etc/wireguard/*
	fi

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system
		if [[ ${Container} == 1 ]]; then
			# In container environments, systemd may not be available; bring it up directly.
			# wg-quick will invoke the userspace implementation when set.
			if command -v amneziawg-go &>/dev/null; then
				export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
			fi
			wg-quick up "${SERVER_WG_NIC}"
		else
			systemctl start "wg-quick@${SERVER_WG_NIC}"
			systemctl enable "wg-quick@${SERVER_WG_NIC}"
		fi
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
	# Default missing routing flags (for older /etc/wireguard/params or manual runs)
	CLIENT_ROUTE_IPV4=${CLIENT_ROUTE_IPV4:-1}
	CLIENT_ROUTE_IPV6=${CLIENT_ROUTE_IPV6:-1}

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
		if [[ -n ${SERVER_WG_IPV4} ]]; then
			DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
			if [[ ${DOT_EXISTS} == '0' ]]; then
				break
			fi
		else
			DOT_EXISTS=0
			break
		fi
	done

	if [[ -n ${SERVER_WG_IPV4} && ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	if [[ -n ${SERVER_WG_IPV4} && ${CLIENT_ROUTE_IPV4} -eq 1 ]]; then
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
	fi

	if [[ -n ${SERVER_WG_IPV6} && ${CLIENT_ROUTE_IPV6} -eq 1 ]]; then
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
	fi

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file and add the server as a peer
	{
		echo "[Interface]"
		echo "PrivateKey = ${CLIENT_PRIV_KEY}"
		if [[ -n ${CLIENT_WG_IPV4} ]]; then
			echo "Address = ${CLIENT_WG_IPV4}/32"
		fi
		if [[ -n ${CLIENT_WG_IPV6} ]]; then
			echo "Address = ${CLIENT_WG_IPV6}/128"
		fi
		echo "DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}"

		echo ""
		echo "# Uncomment the next line to set a custom MTU"
		echo "# This might impact performance, so use it only if you know what you are doing"
		echo "# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU"
		echo "# MTU = 1420"

		echo ""
		echo "[Peer]"
		echo "PublicKey = ${SERVER_PUB_KEY}"
		echo "PresharedKey = ${CLIENT_PRE_SHARED_KEY}"
		echo "Endpoint = ${ENDPOINT}"
		echo "AllowedIPs = ${ALLOWED_IPS}"
	} >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	{
		echo ""
		echo "### Client ${CLIENT_NAME}"
		echo "[Peer]"
		echo "PublicKey = ${CLIENT_PUB_KEY}"
		echo "PresharedKey = ${CLIENT_PRE_SHARED_KEY}"
		if [[ -n ${CLIENT_WG_IPV4} && -n ${CLIENT_WG_IPV6} ]]; then
			echo "AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128"
		elif [[ -n ${CLIENT_WG_IPV4} ]]; then
			echo "AllowedIPs = ${CLIENT_WG_IPV4}/32"
		else
			echo "AllowedIPs = ${CLIENT_WG_IPV6}/128"
		fi
	} >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

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

		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get autoremove --purge -y wireguard wireguard-tools qrencode
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
