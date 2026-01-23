# ⚡️Tesla SSH VPN Reseller Dashboard

Professional web panel for managing SSH/VPN services and reseller accounts. Designed for VPS-based VPN enablers who need a reliable, centrally-managed interface to provision users, configure protocols and monitor usage.

## 🚀 Key features
- One-click installation and automated service configuration
- Monitor bandwidth usage per user
- Support for multiple tunnel/proxy protocols (see list below)
- Add users to only specific protocols they pay for
- Auto ban expired users
- And many more you will discover when you install.

## ♻️ Supported protocols
- V2Ray: VMESS, VLESS
- SSH Proxy (WebSocket)
- SSH over SSL/TLS (stunnel-like setups)
- UDP CUSTOM (SSH UDP)
- SOCKSIP (UDP REQUEST)
- DNSTT / SlowDNS tunneling
- WireGuard (UDP)

## Supported OS (tested)
- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS

These are the platforms validated during development — other Debian/Ubuntu derivatives may work but are not officially tested.

## Requirements & recommendations
- A clean VPS with a supported Ubuntu release
- Root (or sudo) access to perform installation and network configuration
- Minimum 1 vCPU, 1–2 GB RAM (recommended for low-to-medium user counts)
- Optional: a public static IP and a domain name with DNS A record for the panel

## Installation (quick)
Update the system, then run the installer script (the installer will prompt for any required input):

1. Update OS packages
```bash
sudo apt update && sudo apt -y upgrade
```

2. Run the automated installer
```bash
wget --no-cache -O inst.sh "https://raw.githubusercontent.com/teslasshx/vps-manager/refs/heads/main/install.sh"
chmod +x inst.sh && sudo ./inst.sh
```

The installer automates package installation, certificate handling, and service setup.

## Post-installation & verification
- After installtion is complete, visit the dashboard by going to http://your_server_ip. You may as well just visit your cloudflare domain if you already set up the A records to point to your VPS.
- The login username by default is admin. Password will be displayed in the terminal when installation is complete.
- If using a firewall, allow the panel and protocol ports (example using ufw):


## Troubleshooting
- Ensure required ports are not blocked by your provider's network policies.
- If a protocol fails to connect, verify firewall rules and that the corresponding service is running.

## Contributing & Support
Contributions, bug reports and feature requests are welcome. Open an issue on the repository or contact the maintainer.

## Contact
Developer: [teslasshx/vps-manager](https://t.me/teslasshx)
