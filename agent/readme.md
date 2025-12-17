Some pre-built prompts reference absolute paths tailored to my Kali Linux setup. If a prompt fails, update the paths to match your environment.

Tips:
- Search the `agent` folder for `/home/kali` or other absolute paths and replace them with your local paths.
- Prefer using environment variables (for example, `$HOME` or `$KALI_MCP_DIR`) in prompts so they work across systems.

Example — replace hardcoded path:

```bash
# original in prompt
/home/kali/Desktop/mcp/rev.md

# replace with an environment-aware path in your shell config
export KALI_MCP_DIR="$HOME/Desktop/mcp"

# then use: $KALI_MCP_DIR/rev.md
```

If you'd like, I can scan the repository and replace common hardcoded paths with variables or relative paths.