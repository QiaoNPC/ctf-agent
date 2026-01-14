## Kali Linux — Setup

This document contains concise setup steps for tools used with the repo.

**Prerequisites:**
- Ensure Kali is up-to-date and you have `sudo` privileges.
- `dotnet` SDK required for `ilspycmd` and `npm` for Codex CLI.

**Install tools**

1. Update package lists and install `jadx`:

```bash
sudo apt update
sudo apt install -y jadx
```

2. Install `ilspycmd` (requires the .NET SDK):

```bash
dotnet tool install --global ilspycmd
```

3. Install the Codex CLI (NPM) and log in:

```bash
npm i -g @openai/codex
codex
```

**Run MCP server on Kali**

The MCP server script in this repo should be placed on Kali:

- [flarevm.py](/mcp-servers/flarevm/flarevm.py)
- [rag db server](/mcp-servers/ragdb/server.py)

**IDA Pro compatibility**

Note: [flarevm.py](/mcp-servers/flarevm.py) is intended for IDA Pro 9.1. If you are running IDA Pro 9.0, use the alternative server at: [Ong Zi Xuan FlareVM MCP](https://github.com/zixuantemp/flarevm-mcp)

**Optional: add a shell alias**

To create a convenient alias to run the local agent from your shell, add the following to your `~/.zshrc` or `~/.bashrc` (adjust the path to `rev.md` as needed):

```bash
nano ~/.zshrc
```

Add the following at the end of the file:
```bash
alias rev-agent='codex "$(cat /home/kali/Desktop/mcp/rev.md)" --ask-for-approval never --sandbox workspace-write'
alias crypto-agent='codex "$(cat /home/kali/Desktop/mcp/crypto.md)" --ask-for-approval never --sandbox workspace-write'
```

```bash
source ~/.zshrc
```

Adjust the `cat` path if your `rev.md` is located elsewhere.

---

Once you are done, you can register this MCP in Codex
```bash
codex mcp add flarevm -- python3 /full/path/to/server.py
codex mcp add ragdb -- python3 /full/path/to/server.py
```