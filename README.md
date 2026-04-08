# WireGuard / AmneziaWG installer

![Lint](https://github.com/angristan/wireguard-install/workflows/Lint/badge.svg)
[![Say Thanks!](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/angristan)

**This project is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) / AmneziaWG VPN on a Linux server, as easily as possible!**

WireGuard is a point-to-point VPN that can be used in different ways. Here, we mean a VPN as in: the client will forward all its traffic through an encrypted tunnel to the server.
The server will apply NAT to the client's traffic so it will appear as if the client is browsing the web with the server's IP.

The script supports both IPv4 and IPv6, including setups where IPv4 and IPv6 egress use different network interfaces. It also supports IPv6-only servers using 464XLAT/CLAT.

Please check the [issues](https://github.com/angristan/wireguard-install/issues) for ongoing development, bugs and planned features! You might also want to check the [discussions](https://github.com/angristan/wireguard-install/discussions) for help.

WireGuard does not fit your environment? Check out [openvpn-install](https://github.com/angristan/openvpn-install).

## Requirements

Supported distributions:

- AlmaLinux >= 8
- Alpine Linux
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- Oracle Linux
- Rocky Linux >= 8
- Ubuntu >= 18.04

**Testing status:** while the script includes logic for all distributions listed above, it is **only tested on Debian at the moment**.

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest.

```bash
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

### Backend selection (WireGuard vs AmneziaWG)

On first install, the script prompts you to choose a backend:

- **WireGuard (upstream)**: standard WireGuard tooling and configuration
- **AmneziaWG**: WireGuard-compatible, with optional AmneziaWG-specific obfuscation fields in generated client configs

After install, rerunning the script brings up a management menu which includes an option to **switch backends** later.

### What gets installed

Depending on the backend choice and your environment, it will install and configure:

- **WireGuard backend**
  - Defaults to **kernel WireGuard** when available
  - If kernel WireGuard is unavailable (common in containers), or if you explicitly choose userspace, it uses **userspace `wireguard-go`** via `wg-quick`
  - Installs `wireguard-tools` (and `wireguard-go` when needed)
- **AmneziaWG backend**
  - On **VMs / bare metal**: best-effort install of **AmneziaWG DKMS + tools** (when available for your distro)
  - In **containers**: **userspace `amneziawg-go`** plus tooling (kernel modules are often unavailable in containers)

It then configures the server, enables routing/firewall rules for the detected IP stack, and generates client configuration files.

Run the script again to manage clients (the script returns to a management menu after install).

### Client configs

For each client, the script generates **two files**:

- A **standard WireGuard-compatible** client config (no AmneziaWG-only fields)
- An **AmneziaWG-enhanced** client config (includes AmneziaWG obfuscation parameters)

If `qrencode` is installed, it prints QR codes for both.

### NAT / CGNAT / public endpoint detection

The installer tries to pre-fill a reasonable **endpoint address** for clients:

- If the detected IPv4 address is a **private LAN address** (RFC1918), the installer attempts to detect your **external/public IPv4** online and uses it as the default endpoint.
  - In that case, you typically need to **port-forward UDP** on your router/NAT:
    - **WAN UDP port**: the chosen WireGuard port
    - **LAN destination**: your server’s private IP on the same UDP port
- If the detected IPv4 address is **CGNAT** (`100.64.0.0/10`) and a global **IPv6** is available, the installer defaults the endpoint to **IPv6** (because inbound port-forwarding usually isn’t possible with CGNAT).

### DNS

The installer can:

- Detect the host’s DNS resolvers (including common `systemd-resolved` setups)
- Offer a menu of public DNS providers
- Accept custom DNS resolvers (IPv4 or IPv6)

## Providers

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://www.vultr.com/?ref=8948982-8H): Worldwide locations, IPv6 support, starting at \$5/month
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Germany, Finland and USA. IPv6, 20 TB of traffic, starting at 4.5€/month
- [Digital Ocean](https://m.do.co/c/ed0ba143fe53): Worldwide locations, IPv6 support, starting at \$4/month

## Contributing

Contributions are welcome! Here's how you can help:

### Discuss changes

Please open an issue before submitting a PR if you want to discuss a change, especially if it's a big one.

### Code formatting

We use [shellcheck](https://github.com/koalaman/shellcheck) and [shfmt](https://github.com/mvdan/sh) to enforce bash styling guidelines and good practices. They are executed for each commit / PR with GitHub Actions, so you can check the configuration [here](https://github.com/angristan/wireguard-install/blob/master/.github/workflows/lint.yml).

## Say thanks

You can [say thanks](https://saythanks.io/to/angristan) if you want!

## Credits & Licence

This project is under the [MIT Licence](https://raw.githubusercontent.com/angristan/wireguard-install/master/LICENSE)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=angristan/wireguard-install&type=Date)](https://star-history.com/#angristan/wireguard-install&Date)
