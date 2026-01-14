
## ctf-agent

ctf-agent provides a lightweight set of tools and helpers to run an automated agent for solving CTF challenges.

Overview

- Supports solving reverse-engineering and cryptography challenges using native Kali Linux tools and optional Flare VM tooling for Windows-specific binaries.
- Integrates with a `flare-vm` MCP server and a `rag-db` service to speed lookups and script generation.

Features

- Reverse engineering: automates analysis and testing of binaries using Kali or Flare VM tools.
- Cryptography: uses `rag-db` for quick writeup lookups and reusable helper scripts.

Quick start

1. Set up Flare VM (if you need Windows tooling): see [Flare VM setup](flare-vm-setup.md).
2. Prepare a Kali instance: see [Kali setup](kali-linux-setup.md).
3. Start the agent and point it to your `flare-vm` MCP server and `rag-db`.

For more details and advanced configuration, check the project docs in the `agent/` and `mcp-servers/` folders.

