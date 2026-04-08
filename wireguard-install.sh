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
			echo "Continuing in container mode."
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
			echo "Continuing in container mode."
			read -rp "Press enter to continue at your own risk, or CTRL-C to quit."
			Container=1
		fi
	fi
}

function kernelWireGuardAvailable() {
	# Returns 0 if the kernel can create a wireguard interface, 1 otherwise.
	# This is more reliable than grepping lsmod/config across distros/containers.
	if ip link add wg999 type wireguard 2>/dev/null; then
		ip link del wg999 2>/dev/null || true
		return 0
	fi
	return 1
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

function ensureAmneziaWGRepos() {
	# Ensure repositories are present for amneziawg-dkms/amneziawg-tools.
	# This is best-effort and distro-dependent.

	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
		installPackages apt-get update
		# Keep dependencies minimal and compatible with Debian (including Trixie).
		installPackages apt-get install -y --no-install-recommends ca-certificates gnupg

		# Add Launchpad PPA: amnezia/ppa
		# Ubuntu: prefer add-apt-repository when available.
		# Debian: add-apt-repository may be missing; we fall back to manual source entry below.
		if ! command -v add-apt-repository &>/dev/null; then
			# Try to install it if the package exists; don't fail if it doesn't (e.g. Debian Trixie).
			apt-get install -y --no-install-recommends software-properties-common >/dev/null 2>&1 || true
		fi
		if command -v add-apt-repository &>/dev/null; then
			add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
		fi

		if ! grep -Rqs "ppa\\.launchpadcontent\\.net/amnezia/ppa" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
			# Manual PPA entry fallback
			source /etc/os-release
			# Launchpad PPAs are published for Ubuntu series names, not Debian codenames.
			# Map Debian releases to an Ubuntu series known to exist for this PPA.
			if [[ ${ID} == "debian" || ${ID} == "raspbian" ]]; then
				case "${VERSION_CODENAME}" in
				trixie)
					PPA_CODENAME="noble"
					;;
				bookworm)
					PPA_CODENAME="focal"
					;;
				*)
					PPA_CODENAME="focal"
					;;
				esac
			else
				PPA_CODENAME="${VERSION_CODENAME}"
				if [[ -z ${PPA_CODENAME} ]]; then
					PPA_CODENAME="focal"
				fi
			fi

			# Import signing key (key id commonly referenced for this PPA)
			# and wire it via signed-by instead of apt-key.
			AMNEZIA_KEYRING="/usr/share/keyrings/amnezia-ppa.gpg"
			if [[ ! -r ${AMNEZIA_KEYRING} ]]; then
				installPackages bash -c "gpg --batch --keyserver keyserver.ubuntu.com --recv-keys 57290828 && gpg --batch --export 57290828 | gpg --batch --dearmor -o '${AMNEZIA_KEYRING}'"
			fi

			cat > /etc/apt/sources.list.d/amnezia-ppa.list <<EOF
deb [signed-by=${AMNEZIA_KEYRING}] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu ${PPA_CODENAME} main
EOF
		fi

		installPackages apt-get update
	elif [[ ${OS} == 'fedora' ]]; then
		installPackages dnf install -y dnf-plugins-core
		dnf copr enable -y amneziavpn/amneziawg >/dev/null 2>&1 || true
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
		installPackages dnf -y install 'dnf-command(copr)' || true
		installPackages yum -y install yum-plugin-copr || true
		(dnf copr enable -y amneziavpn/amneziawg >/dev/null 2>&1 || true)
		(yum copr enable -y amneziavpn/amneziawg >/dev/null 2>&1 || true)
	fi
}

function installAmneziaWGKernel() {
	# Best-effort DKMS install for bare metal/VMs.
	# Package availability depends on distro/repositories.
	ensureAmneziaWGRepos
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

function selectWgImplementation() {
	# Pick tooling based on selected backend (persisted in /etc/wireguard/params).
	# WG_BACKEND values:
	# - wireguard  : upstream WireGuard (kernel or wireguard-go userspace)
	# - amneziawg  : AmneziaWG (kernel via DKMS or amneziawg-go userspace)
	WG_BACKEND=${WG_BACKEND:-amneziawg}

	WG_CMD="wg"
	WG_QUICK_CMD="wg-quick"
	unset WG_QUICK_USERSPACE_IMPLEMENTATION

	if [[ ${WG_BACKEND} == "amneziawg" ]]; then
		# Prefer AmneziaWG tooling when present.
		if command -v awg &>/dev/null; then
			WG_CMD="awg"
		fi
		if command -v awg-quick &>/dev/null; then
			WG_QUICK_CMD="awg-quick"
		fi
		# Userspace amneziawg-go: tell quick helper which userspace backend to use
		if command -v amneziawg-go &>/dev/null; then
			export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
		fi
	else
		# WireGuard backend.
		# Userspace wireguard-go: tell wg-quick which backend to use when requested/required.
		if [[ ${WG_USE_USERSPACE} == 1 ]] && command -v wireguard-go &>/dev/null; then
			export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
		fi
	fi
}

function ensureAmneziaPaths() {
	# Prefer a single configuration directory by linking AmneziaWG path to /etc/wireguard.
	# Desired state:
	# - /etc/wireguard exists (real directory)
	# - /etc/amnezia/amneziawg -> /etc/wireguard (symlink)
	mkdir -p /etc/amnezia

	# If /etc/amnezia/amneziawg exists and isn't the desired symlink, remove it.
	if [[ -e /etc/amnezia/amneziawg || -L /etc/amnezia/amneziawg ]]; then
		if [[ -L /etc/amnezia/amneziawg ]] && [[ $(readlink /etc/amnezia/amneziawg) == "/etc/wireguard" ]]; then
			return 0
		fi
		rm -rf /etc/amnezia/amneziawg
	fi

	ln -s /etc/wireguard /etc/amnezia/amneziawg
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
	selectWgImplementation
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

function isPrivateIPv4() {
	# RFC1918 + CGNAT (RFC6598)
	# Returns 0 when the IPv4 is private/non-routable for typical "public endpoint" usage.
	local IP=$1
	local A B C D

	if ! isValidIPv4 "${IP}"; then
		return 1
	fi

	IFS='.' read -r A B C D <<<"${IP}"

	# 10.0.0.0/8
	if [[ ${A} -eq 10 ]]; then
		return 0
	fi
	# 172.16.0.0/12
	if [[ ${A} -eq 172 && ${B} -ge 16 && ${B} -le 31 ]]; then
		return 0
	fi
	# 192.168.0.0/16
	if [[ ${A} -eq 192 && ${B} -eq 168 ]]; then
		return 0
	fi

	return 1
}

function isCgnatIPv4() {
	# 100.64.0.0/10 (Carrier-grade NAT, RFC6598)
	# Returns 0 if IP is in CGNAT range.
	local IP=$1
	local A B C D

	if ! isValidIPv4 "${IP}"; then
		return 1
	fi
	IFS='.' read -r A B C D <<<"${IP}"
	if [[ ${A} -eq 100 && ${B} -ge 64 && ${B} -le 127 ]]; then
		return 0
	fi
	return 1
}

function detectExternalIPv4() {
	# Best-effort external IPv4 discovery (behind NAT / private local address).
	# Prints the IP (stdout) on success, returns 0. Returns 1 otherwise.
	local IP=""
	local URLS=(
		"https://api.ipify.org"
		"https://ipv4.icanhazip.com"
		"https://ifconfig.co/ip"
	)

	if command -v curl &>/dev/null; then
		for u in "${URLS[@]}"; do
			IP="$(curl -4 -fsS --max-time 8 "${u}" 2>/dev/null | tr -d ' \t\r\n' || true)"
			if isValidIPv4 "${IP}" && ! isPrivateIPv4 "${IP}"; then
				echo "${IP}"
				return 0
			fi
		done
	elif command -v wget &>/dev/null; then
		for u in "${URLS[@]}"; do
			IP="$(wget -4 -qO- --timeout=8 "${u}" 2>/dev/null | tr -d ' \t\r\n' || true)"
			if isValidIPv4 "${IP}" && ! isPrivateIPv4 "${IP}"; then
				echo "${IP}"
				return 0
			fi
		done
	fi

	return 1
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

function generateAmneziaWGClientObfuscation() {
	# AmneziaWG-specific client-side obfuscation parameters.
	# These are intended to be used by AmneziaWG clients/tools; standard WireGuard clients
	# may not understand them.
	#
	# Based on amneziawg-go documentation:
	# - If no value specified, AWG treats it as 0 (disabled)
	# - Junk packets (Jc/Jmin/Jmax) and custom signature packets (I1-I5) are generally
	#   recommended on the client side only.

	# Junk packets (client-side)
	AWG_JC=$(shuf -i4-12 -n1)
	AWG_JMIN=$(shuf -i40-200 -n1)
	AWG_JMAX=$(shuf -i200-600 -n1)
	if [[ ${AWG_JMAX} -lt ${AWG_JMIN} ]]; then
		local TMP=${AWG_JMIN}
		AWG_JMIN=${AWG_JMAX}
		AWG_JMAX=${TMP}
	fi

	# Signature packets (client-side). Kept small to avoid MTU issues.
	# Uses tags: <t> timestamp, <r N> random bytes, <rd N> random digits, <rc N> random chars.
	AWG_I1="<t><r 8>"
	AWG_I2="<r 12>"
	AWG_I3="<t><rd 12>"
	AWG_I4="<rc 16>"
	AWG_I5=""
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Backend selection (first install only).
	if [[ -z ${WG_BACKEND} ]]; then
		echo "Select the VPN backend to install:"
		echo "   1) WireGuard (upstream)"
		echo "   2) AmneziaWG (WireGuard-compatible + obfuscation options)"
		echo ""
		until [[ ${WG_BACKEND_MENU} =~ ^[1-2]$ ]]; do
			read -rp "Select an option [2]: " WG_BACKEND_MENU
			WG_BACKEND_MENU=${WG_BACKEND_MENU:-2}
		done
		case "${WG_BACKEND_MENU}" in
		1) WG_BACKEND="wireguard" ;;
		2) WG_BACKEND="amneziawg" ;;
		esac
	fi

	detectIPStack
	generateRandomTunnelPrefix
	generateAmneziaWGClientObfuscation
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

	# NAT helper (pre-fill):
	# - If the detected IPv4 looks RFC1918, try to default the prompt to the external IPv4.
	# - If the detected IPv4 looks CGNAT and IPv6 is available, default to IPv6 (port-forwarding likely impossible).
	DETECTED_LAN_IPV4=""
	DETECTED_EXT_IPV4=""
	DETECTED_GLOBAL_IPV6=""
	SERVER_PUB_IP_DEFAULT="${SERVER_PUB_IP}"

	if [[ ${IPV6_AVAILABLE} -eq 1 ]]; then
		DETECTED_GLOBAL_IPV6="$(ip -6 addr show ${SERVER_NIC6:+dev "${SERVER_NIC6}"} scope global 2>/dev/null | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
		if [[ -z ${DETECTED_GLOBAL_IPV6} ]]; then
			DETECTED_GLOBAL_IPV6="$(ip -6 addr show scope global 2>/dev/null | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
		fi
	fi

	if isValidIPv4 "${SERVER_PUB_IP}" && isCgnatIPv4 "${SERVER_PUB_IP}" && [[ -n ${DETECTED_GLOBAL_IPV6} ]]; then
		echo ""
		echo -e "${ORANGE}Detected IPv4 (${SERVER_PUB_IP}) appears to be CGNAT (100.64.0.0/10).${NC}"
		echo "Most CGNAT connections cannot receive inbound port-forwards."
		echo "Since IPv6 is available, the default endpoint will be set to your IPv6 address instead."
		SERVER_PUB_IP_DEFAULT="${DETECTED_GLOBAL_IPV6}"
	elif isValidIPv4 "${SERVER_PUB_IP}" && isPrivateIPv4 "${SERVER_PUB_IP}"; then
		DETECTED_LAN_IPV4="${SERVER_PUB_IP}"
		DETECTED_EXT_IPV4="$(detectExternalIPv4 || true)"
		if [[ -n ${DETECTED_EXT_IPV4} ]]; then
			echo ""
			echo -e "${ORANGE}Detected IPv4 (${SERVER_PUB_IP}) looks like a private LAN address.${NC}"
			echo "This host may be behind NAT. The default endpoint will be set to the detected external IPv4."
			SERVER_PUB_IP_DEFAULT="${DETECTED_EXT_IPV4}"
		fi
	fi

	read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP_DEFAULT}" SERVER_PUB_IP

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

	# If we detected a LAN IPv4 and user chose an external endpoint, print port-forwarding guidance.
	if [[ -n ${DETECTED_LAN_IPV4} ]] && isValidIPv4 "${DETECTED_LAN_IPV4}"; then
		if isValidIPv4 "${SERVER_PUB_IP}" && ! isPrivateIPv4 "${SERVER_PUB_IP}" && ! isCgnatIPv4 "${SERVER_PUB_IP}"; then
			echo ""
			echo -e "${ORANGE}NAT / port-forwarding note:${NC}"
			echo "It looks like this server is on a private LAN address (${DETECTED_LAN_IPV4})."
			echo "To allow internet clients to connect, configure your router/NAT to forward:"
			echo "  - External (WAN) UDP port: ${SERVER_PORT}"
			echo "  - Internal (LAN) destination: ${DETECTED_LAN_IPV4}:${SERVER_PORT} (UDP)"
			echo ""
			echo "Also ensure the router/firewall allows inbound UDP ${SERVER_PORT}."
		fi
	fi

	# If the chosen endpoint is still CGNAT IPv4 and IPv6 exists, warn the user.
	if isValidIPv4 "${SERVER_PUB_IP}" && isCgnatIPv4 "${SERVER_PUB_IP}" && [[ -n ${DETECTED_GLOBAL_IPV6} ]]; then
		echo ""
		echo -e "${ORANGE}CGNAT note:${NC}"
		echo "Your selected IPv4 endpoint (${SERVER_PUB_IP}) is CGNAT. Inbound port-forwarding is usually not possible."
		echo "If you want this to work from the internet, prefer using your IPv6 endpoint (${DETECTED_GLOBAL_IPV6})"
		echo "or obtain a public IPv4 / use a VPN/relay solution."
	fi

	# WireGuard userspace selection: default to kernel when possible.
	if [[ ${WG_BACKEND} == "wireguard" ]]; then
		if kernelWireGuardAvailable; then
			read -rp "Use userspace WireGuard (wireguard-go) instead of kernel module? [y/N]: " -e WG_USERSPACE_ANSWER
			WG_USERSPACE_ANSWER=${WG_USERSPACE_ANSWER:-N}
			if [[ ${WG_USERSPACE_ANSWER} =~ ^[Yy]$ ]]; then
				WG_USE_USERSPACE=1
			else
				WG_USE_USERSPACE=0
			fi
		else
			echo ""
			echo -e "${ORANGE}Kernel WireGuard is not available on this system.${NC}"
			echo "WireGuard will be installed in userspace using wireguard-go."
			WG_USE_USERSPACE=1
		fi
	else
		# AmneziaWG: in containers we will likely need userspace; handled later.
		WG_USE_USERSPACE=0
	fi

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

function installWireguardGo() {
	# Install wireguard-go userspace implementation.
	if command -v wireguard-go &>/dev/null; then
		return 0
	fi
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
		apt-get update
		installPackages apt-get install -y --no-install-recommends wireguard-go
	elif [[ ${OS} == 'fedora' ]]; then
		installPackages dnf install -y wireguard-tools wireguard-go || true
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
		installPackages yum install -y wireguard-tools wireguard-go || true
		installPackages dnf install -y wireguard-tools wireguard-go || true
	elif [[ ${OS} == 'arch' ]]; then
		installPackages pacman -S --needed --noconfirm wireguard-go
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		installPackages apk add wireguard-go
	fi
}

function pruneOtherBackendPackages() {
	# Best-effort removal of packages/binaries for the backend not in use.
	# Goal: avoid having both toolchains installed at once.
	checkOS

	if [[ ${WG_BACKEND} == "wireguard" ]]; then
		# Remove AmneziaWG tooling.
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get remove -y --purge amneziawg-tools amneziawg-dkms >/dev/null 2>&1 || true
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove amneziawg-tools amneziawg-dkms >/dev/null 2>&1 || true
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
			yum remove -y --noautoremove amneziawg-tools amneziawg-dkms >/dev/null 2>&1 || true
			dnf remove -y --noautoremove amneziawg-tools amneziawg-dkms >/dev/null 2>&1 || true
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rns --noconfirm amneziawg-tools amneziawg-dkms >/dev/null 2>&1 || true
		elif [[ ${OS} == 'alpine' ]]; then
			apk del amneziawg-tools >/dev/null 2>&1 || true
		fi
		rm -f /usr/local/bin/amneziawg-go >/dev/null 2>&1 || true
	else
		# Remove WireGuard userspace tool (wireguard-go) when using AmneziaWG.
		# Keep wireguard-tools only when we don't have amneziawg-tools (container fallback).
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get remove -y --purge wireguard-go >/dev/null 2>&1 || true
			if command -v awg &>/dev/null; then
				apt-get remove -y --purge wireguard-tools >/dev/null 2>&1 || true
			fi
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-go >/dev/null 2>&1 || true
			if command -v awg &>/dev/null; then
				dnf remove -y --noautoremove wireguard-tools >/dev/null 2>&1 || true
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
			yum remove -y --noautoremove wireguard-go >/dev/null 2>&1 || true
			dnf remove -y --noautoremove wireguard-go >/dev/null 2>&1 || true
			if command -v awg &>/dev/null; then
				yum remove -y --noautoremove wireguard-tools >/dev/null 2>&1 || true
				dnf remove -y --noautoremove wireguard-tools >/dev/null 2>&1 || true
			fi
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rns --noconfirm wireguard-go >/dev/null 2>&1 || true
			if command -v awg &>/dev/null; then
				pacman -Rns --noconfirm wireguard-tools >/dev/null 2>&1 || true
			fi
		elif [[ ${OS} == 'alpine' ]]; then
			apk del wireguard-go >/dev/null 2>&1 || true
			if command -v awg &>/dev/null; then
				apk del wireguard-tools >/dev/null 2>&1 || true
			fi
		fi
		rm -f /usr/local/bin/wireguard-go >/dev/null 2>&1 || true
	fi
}

function installWireGuardBackendPackages() {
	# Upstream WireGuard tools (wg/wg-quick) + optional wireguard-go.
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
		apt-get update
		installPackages apt-get install -y iptables resolvconf qrencode
		installPackages apt-get install -y --no-install-recommends wireguard-tools
		if [[ ${WG_USE_USERSPACE} == 1 ]]; then
			installWireguardGo
		fi
	elif [[ ${OS} == 'fedora' ]]; then
		installPackages dnf install -y wireguard-tools iptables qrencode || true
		if [[ ${WG_USE_USERSPACE} == 1 ]]; then
			installWireguardGo
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		installPackages yum install -y wireguard-tools iptables qrencode || true
		installPackages dnf install -y wireguard-tools iptables qrencode || true
		if [[ ${WG_USE_USERSPACE} == 1 ]]; then
			installWireguardGo
		fi
	elif [[ ${OS} == 'oracle' ]]; then
		installPackages dnf install -y wireguard-tools qrencode iptables || true
		if [[ ${WG_USE_USERSPACE} == 1 ]]; then
			installWireguardGo
		fi
	elif [[ ${OS} == 'arch' ]]; then
		installPackages pacman -S --needed --noconfirm wireguard-tools qrencode
		if [[ ${WG_USE_USERSPACE} == 1 ]]; then
			installWireguardGo
		fi
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		installPackages apk add wireguard-tools iptables libqrencode-tools
		if [[ ${WG_USE_USERSPACE} == 1 ]]; then
			installWireguardGo
		fi
	fi
}

function installAmneziaWGBackendPackages() {
	# Install AmneziaWG (preferred) / tools
	#
	# - Bare metal / VM: install kernel module via DKMS (amneziawg-dkms) + tools
	# - Container: install userspace amneziawg-go + (amneziawg-tools if available, else wireguard-tools)
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		installPackages apt-get install -y iptables resolvconf qrencode
		if [[ ${Container} == 1 ]]; then
			ensureAmneziaWGRepos
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
			ensureAmneziaWGRepos
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
}

function installWireGuard() {
	checkVirt
	# Run setup questions first
	installQuestions

	# If we are in a container without kernel WireGuard and user selected upstream WireGuard,
	# force userspace implementation (wireguard-go).
	if [[ ${WG_BACKEND} == "wireguard" ]] && [[ ${Container} == 1 ]]; then
		if ! kernelWireGuardAvailable; then
			WG_USE_USERSPACE=1
		fi
	fi

	if [[ ${WG_BACKEND} == "wireguard" ]]; then
		installWireGuardBackendPackages
	else
		installAmneziaWGBackendPackages
	fi

	# Remove packages/binaries from the non-selected backend.
	# This is best-effort and should not make the install fail.
	pruneOtherBackendPackages

	# Re-select tooling now that packages are installed
	selectWgImplementation

	# Verify installation (either wg or awg must exist)
	if ! command -v "${WG_CMD}" &>/dev/null; then
		echo -e "${RED}Installation failed. Neither 'awg' nor 'wg' was found.${NC}"
		echo "Please check the installation output above for errors."
		exit 1
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1
	ensureAmneziaPaths

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$("${WG_CMD}" genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | "${WG_CMD}" pubkey)

	# Save WireGuard settings (printf %q so AmneziaWG I1–I5 patterns with <, >, spaces are source-safe)
	{
		printf 'WG_BACKEND=%q\n' "${WG_BACKEND}"
		printf 'WG_USE_USERSPACE=%q\n' "${WG_USE_USERSPACE:-0}"
		printf 'SERVER_PUB_IP=%q\n' "${SERVER_PUB_IP}"
		printf 'SERVER_PUB_NIC=%q\n' "${SERVER_PUB_NIC}"
		printf 'SERVER_PUB_NIC4=%q\n' "${SERVER_PUB_NIC4}"
		printf 'SERVER_PUB_NIC6=%q\n' "${SERVER_PUB_NIC6}"
		printf 'SERVER_WG_NIC=%q\n' "${SERVER_WG_NIC}"
		printf 'SERVER_WG_IPV4=%q\n' "${SERVER_WG_IPV4}"
		printf 'SERVER_WG_IPV6=%q\n' "${SERVER_WG_IPV6}"
		printf 'IPV4_AVAILABLE=%q\n' "${IPV4_AVAILABLE}"
		printf 'IPV6_AVAILABLE=%q\n' "${IPV6_AVAILABLE}"
		printf 'CLAT_PRESENT=%q\n' "${CLAT_PRESENT}"
		printf 'CLIENT_ROUTE_IPV4=%q\n' "${CLIENT_ROUTE_IPV4}"
		printf 'CLIENT_ROUTE_IPV6=%q\n' "${CLIENT_ROUTE_IPV6}"
		printf 'AWG_JC=%q\n' "${AWG_JC}"
		printf 'AWG_JMIN=%q\n' "${AWG_JMIN}"
		printf 'AWG_JMAX=%q\n' "${AWG_JMAX}"
		printf 'AWG_I1=%q\n' "${AWG_I1}"
		printf 'AWG_I2=%q\n' "${AWG_I2}"
		printf 'AWG_I3=%q\n' "${AWG_I3}"
		printf 'AWG_I4=%q\n' "${AWG_I4}"
		printf 'AWG_I5=%q\n' "${AWG_I5}"
		printf 'SERVER_PORT=%q\n' "${SERVER_PORT}"
		printf 'SERVER_PRIV_KEY=%q\n' "${SERVER_PRIV_KEY}"
		printf 'SERVER_PUB_KEY=%q\n' "${SERVER_PUB_KEY}"
		printf 'CLIENT_DNS_1=%q\n' "${CLIENT_DNS_1}"
		printf 'CLIENT_DNS_2=%q\n' "${CLIENT_DNS_2}"
		printf 'ALLOWED_IPS=%q\n' "${ALLOWED_IPS}"
	} >/etc/wireguard/params

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
			selectWgImplementation
			"${WG_QUICK_CMD}" up "${SERVER_WG_NIC}"
		else
			systemctl start "${WG_QUICK_CMD}@${SERVER_WG_NIC}"
			systemctl enable "${WG_QUICK_CMD}@${SERVER_WG_NIC}"
		fi
	fi

	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "${WG_QUICK_CMD}@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status ${WG_QUICK_CMD}@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status\n\n${NC}"
		else
			echo -e "${GREEN}You can check the status of WireGuard with: systemctl status ${WG_QUICK_CMD}@${SERVER_WG_NIC}\n\n${NC}"
		fi
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	# Clear transient state so repeated runs don't reuse previous answers.
	unset CLIENT_NAME CLIENT_EXISTS CLIENT_NUMBER DOT_IP DOT_EXISTS BASE_IP
	unset IPV4_EXISTS IPV6_EXISTS CLIENT_WG_IPV4 CLIENT_WG_IPV6

	# Default missing routing flags (for older /etc/wireguard/params or manual runs)
	CLIENT_ROUTE_IPV4=${CLIENT_ROUTE_IPV4:-1}
	CLIENT_ROUTE_IPV6=${CLIENT_ROUTE_IPV6:-1}

	# Default missing AWG obfuscation settings (older /etc/wireguard/params)
	if [[ -z ${AWG_JC} || -z ${AWG_JMIN} || -z ${AWG_JMAX} ]]; then
		generateAmneziaWGClientObfuscation
	fi
	AWG_I1=${AWG_I1:-}
	AWG_I2=${AWG_I2:-}
	AWG_I3=${AWG_I3:-}
	AWG_I4=${AWG_I4:-}
	AWG_I5=${AWG_I5:-}

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
	CLIENT_PRIV_KEY=$("${WG_CMD}" genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | "${WG_CMD}" pubkey)
	CLIENT_PRE_SHARED_KEY=$("${WG_CMD}" genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file and add the server as a peer
	BASE_CLIENT_CONFIG_PATH="${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	AWG_CLIENT_CONFIG_PATH="${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}-amneziawg.conf"

	# Standard WireGuard-compatible client config
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
	} >"${BASE_CLIENT_CONFIG_PATH}"

	# AmneziaWG-enhanced client config (obfuscation options belong in [Interface])
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
		echo "Jc = ${AWG_JC}"
		echo "Jmin = ${AWG_JMIN}"
		echo "Jmax = ${AWG_JMAX}"
		if [[ -n ${AWG_I1} ]]; then echo "I1 = ${AWG_I1}"; fi
		if [[ -n ${AWG_I2} ]]; then echo "I2 = ${AWG_I2}"; fi
		if [[ -n ${AWG_I3} ]]; then echo "I3 = ${AWG_I3}"; fi
		if [[ -n ${AWG_I4} ]]; then echo "I4 = ${AWG_I4}"; fi
		if [[ -n ${AWG_I5} ]]; then echo "I5 = ${AWG_I5}"; fi

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
	} >"${AWG_CLIENT_CONFIG_PATH}"

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

	"${WG_CMD}" syncconf "${SERVER_WG_NIC}" <("${WG_QUICK_CMD}" strip "${SERVER_WG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your standard client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${BASE_CLIENT_CONFIG_PATH}"
		echo ""
		echo -e "${GREEN}Here is your AmneziaWG client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${AWG_CLIENT_CONFIG_PATH}"
		echo ""
	fi

	echo -e "${GREEN}Your standard client config file is in ${BASE_CLIENT_CONFIG_PATH}${NC}"
	echo -e "${GREEN}Your AmneziaWG client config file is in ${AWG_CLIENT_CONFIG_PATH}${NC}"
}

function resetMenuState() {
	# Reset variables that are reused across menu actions.
	unset MENU_OPTION CLIENT_NUMBER CLIENT_NAME
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
	"${WG_CMD}" syncconf "${SERVER_WG_NIC}" <("${WG_QUICK_CMD}" strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard/AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard/AmneziaWG? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop
			rc-update del "wg-quick.${SERVER_WG_NIC}"
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			rc-update del sysctl
		else
			systemctl stop "${WG_QUICK_CMD}@${SERVER_WG_NIC}"
			systemctl disable "${WG_QUICK_CMD}@${SERVER_WG_NIC}"
		fi

		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get autoremove --purge -y wireguard wireguard-tools wireguard-go qrencode amneziawg-tools amneziawg-dkms || true
			# amneziawg-go is installed via go install into /usr/local/bin
			rm -f /usr/local/bin/amneziawg-go || true
			rm -f /usr/local/bin/wireguard-go || true
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools wireguard-go qrencode amneziawg-tools amneziawg-dkms || true
			rm -f /usr/local/bin/amneziawg-go || true
			rm -f /usr/local/bin/wireguard-go || true
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools wireguard-go amneziawg-tools amneziawg-dkms || true
			dnf remove -y --noautoremove wireguard-tools wireguard-go amneziawg-tools amneziawg-dkms || true
			rm -f /usr/local/bin/amneziawg-go || true
			rm -f /usr/local/bin/wireguard-go || true
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools wireguard-go qrencode amneziawg-tools amneziawg-dkms || true
			dnf remove -y --noautoremove wireguard-tools wireguard-go qrencode amneziawg-tools amneziawg-dkms || true
			rm -f /usr/local/bin/amneziawg-go || true
			rm -f /usr/local/bin/wireguard-go || true
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools wireguard-go qrencode amneziawg-tools amneziawg-dkms || true
			rm -f /usr/local/bin/amneziawg-go || true
			rm -f /usr/local/bin/wireguard-go || true
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 || exit && make uninstall)
			rm -rf qrencode-* || exit
			apk del wireguard-tools wireguard-go libqrencode libqrencode-tools amneziawg-tools || true
			rm -f /usr/local/bin/amneziawg-go || true
			rm -f /usr/local/bin/wireguard-go || true
		fi

		# Remove AmneziaWG config dir/link
		rm -rf /etc/amnezia/amneziawg || true
		rmdir /etc/amnezia 2>/dev/null || true

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			# Reload sysctl
			sysctl --system

			# Check if WireGuard is running
			systemctl is-active --quiet "${WG_QUICK_CMD}@${SERVER_WG_NIC}"
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

function restartInterfaceWithBackend() {
	# Stop both units (if any), then start the selected one.
	if [[ ${OS} != 'alpine' ]]; then
		systemctl stop "wg-quick@${SERVER_WG_NIC}" >/dev/null 2>&1 || true
		systemctl stop "awg-quick@${SERVER_WG_NIC}" >/dev/null 2>&1 || true
		systemctl disable "wg-quick@${SERVER_WG_NIC}" >/dev/null 2>&1 || true
		systemctl disable "awg-quick@${SERVER_WG_NIC}" >/dev/null 2>&1 || true
	fi

	selectWgImplementation

	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" stop >/dev/null 2>&1 || true
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" start || true
	elif [[ ${Container} == 1 ]]; then
		"${WG_QUICK_CMD}" down "${SERVER_WG_NIC}" >/dev/null 2>&1 || true
		"${WG_QUICK_CMD}" up "${SERVER_WG_NIC}"
	else
		systemctl start "${WG_QUICK_CMD}@${SERVER_WG_NIC}"
		systemctl enable "${WG_QUICK_CMD}@${SERVER_WG_NIC}"
	fi
}

function switchBackend() {
	echo ""
	echo "Switch VPN backend"
	echo ""
	echo "Current backend: ${WG_BACKEND:-amneziawg}"
	echo ""
	echo "Select the backend to switch to:"
	echo "   1) WireGuard (upstream)"
	echo "   2) AmneziaWG"
	echo ""
	until [[ ${SWITCH_MENU} =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " SWITCH_MENU
	done

	if [[ ${SWITCH_MENU} == 1 ]]; then
		WG_BACKEND="wireguard"
	else
		WG_BACKEND="amneziawg"
	fi

	# Decide userspace requirement for WireGuard.
	if [[ ${WG_BACKEND} == "wireguard" ]]; then
		if kernelWireGuardAvailable; then
			read -rp "Use userspace WireGuard (wireguard-go) instead of kernel module? [y/N]: " -e WG_USERSPACE_ANSWER
			WG_USERSPACE_ANSWER=${WG_USERSPACE_ANSWER:-N}
			if [[ ${WG_USERSPACE_ANSWER} =~ ^[Yy]$ ]]; then
				WG_USE_USERSPACE=1
			else
				WG_USE_USERSPACE=0
			fi
		else
			echo -e "${ORANGE}Kernel WireGuard is not available; using wireguard-go.${NC}"
			WG_USE_USERSPACE=1
		fi
	else
		WG_USE_USERSPACE=0
	fi

	# Ensure packages for the selected backend are present.
	checkOS
	checkVirt
	if [[ ${WG_BACKEND} == "wireguard" ]]; then
		# If in container without kernel support, force userspace.
		if [[ ${Container} == 1 ]] && ! kernelWireGuardAvailable; then
			WG_USE_USERSPACE=1
		fi
		installWireGuardBackendPackages
	else
		installAmneziaWGBackendPackages
	fi

	# Remove packages/binaries from the non-selected backend.
	pruneOtherBackendPackages

	# Persist.
	if [[ -e /etc/wireguard/params ]]; then
		# shellcheck disable=SC2016
		sed -i '/^WG_BACKEND=/d;/^WG_USE_USERSPACE=/d' /etc/wireguard/params
	fi
	{
		printf 'WG_BACKEND=%q\n' "${WG_BACKEND}"
		printf 'WG_USE_USERSPACE=%q\n' "${WG_USE_USERSPACE:-0}"
	} >>/etc/wireguard/params

	# Reload and restart.
	source /etc/wireguard/params
	restartInterfaceWithBackend
}

function manageMenu() {
	while true; do
		resetMenuState
		# Reload persisted parameters in case something changed
		# (e.g. previous run wrote new values, or user edited params).
		if [[ -e /etc/wireguard/params ]]; then
			source /etc/wireguard/params
		fi
		echo "Welcome to WireGuard-install!"
		echo "The git repository is available at: https://github.com/angristan/wireguard-install"
		echo ""
		echo "It looks like WireGuard is already installed."
		echo ""
		echo "Current backend: ${WG_BACKEND:-amneziawg}${WG_USE_USERSPACE:+ (userspace)}"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a new user"
		echo "   2) List all users"
		echo "   3) Revoke existing user"
		echo "   4) Switch backend (WireGuard <-> AmneziaWG)"
		echo "   5) Uninstall WireGuard"
		echo "   6) Exit"
		echo "   q) Quit (same as 6)"
		until [[ ${MENU_OPTION} =~ ^([1-6]|[qQ])$ ]]; do
			read -rp "Select an option [1-6 or q]: " MENU_OPTION
		done
		case "${MENU_OPTION}" in
		1)
			newClient
			read -rp "Press enter to return to the menu..."
			;;
		2)
			listClients
			read -rp "Press enter to return to the menu..."
			;;
		3)
			revokeClient
			read -rp "Press enter to return to the menu..."
			;;
		4)
			switchBackend
			read -rp "Press enter to return to the menu..."
			;;
		5)
			uninstallWg
			;;
		6 | q | Q)
			exit 0
			;;
		esac
	done
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	manageMenu
else
	installWireGuard
	# After initial installation, drop into the menu without requiring a rerun.
	source /etc/wireguard/params
	manageMenu
fi
