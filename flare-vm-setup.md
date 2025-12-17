## flare-vm — Setup

This file documents the minimum Windows-side setup needed for `flare-vm` so an external Kali instance (running the MCP client/server components) can connect.

**Prerequisites**
- `flare-vm` installed and running.
- IDA Pro (install the version that matches your MCP server/plugin).

**IDA MCP compatibility**
- If you use IDA Pro 9.0, [consider the Ong Zi Xuan's](https://github.com/zixuantemp/flarevm-mcp)
- For IDA Pro 9.1 the repo includes a compatible server at [flarevm.py](mcp-servers/flarevm.py).
- [IDA Pro MCP Plugin](https://github.com/mrexodia/ida-pro-mcp)

**Windows configuration (PowerShell — run as Administrator)**

The following commands configure networking, WinRM, and a simple SMB share used by some workflows. Review and adapt usernames, interface names, and security settings for your environment.

```powershell
# Make the specified interface private (adjust InterfaceAlias as needed)
Set-NetConnectionProfile -InterfaceAlias "Ethernet0" -NetworkCategory Private

Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

winrm quickconfig -q
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

New-Item -ItemType Directory -Path C:\Share -Force
New-SmbShare -Name KaliShare -Path C:\Share -FullAccess kali
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
```
