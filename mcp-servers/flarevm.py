#!/usr/bin/env python3
import asyncio
import base64
import json
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types
import winrm
from pathlib import Path
import hashlib
import re
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor

FLAREVM_HOST = "flarevm"
FLAREVM_USER = "kali"
FLAREVM_PASSWORD = "kali"

SMB_SHARE_NAME = "KaliShare"
SMB_SHARE_PATH = f"//{FLAREVM_HOST}/{SMB_SHARE_NAME}"
SMB_LOCAL_PATH = "C:\\Share"


session = winrm.Session(
    FLAREVM_HOST,
    auth=(FLAREVM_USER, FLAREVM_PASSWORD),
    transport='plaintext'
)

executor = ThreadPoolExecutor(max_workers=4)

app = Server("flarevm-remote")

async def run_ps_async(command: str, timeout: int = 120):
    """Run PowerShell command asynchronously with timeout"""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(executor, session.run_ps, command),
            timeout=timeout
        )
        return result
    except asyncio.TimeoutError:
        raise Exception(f"PowerShell command timed out after {timeout} seconds")

def ida_rpc_call(method: str, params: dict = None):
    """Make MCP tool call to IDA Pro MCP server via WinRM"""
    
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": method,
            "arguments": params or {}
        },
        "id": 1
    }
    
    ps_script = f'''
$body = @'
{json.dumps(payload)}
'@
    
try {{
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:13337/mcp" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -UseBasicParsing
    
    $response.Content
}} catch {{
    Write-Output "Error: $($_.Exception.Message)"
}}
'''
    
    result = session.run_ps(ps_script)
    response_text = result.std_out.decode('utf-8', errors='replace').strip()
    
    try:
        response_json = json.loads(response_text)
        if "error" in response_json:
            return {"error": response_json["error"]["message"]}
        
        if "result" in response_json:
            result_data = response_json["result"]
            if isinstance(result_data, dict) and "content" in result_data:
                content_items = result_data["content"]
                if content_items and len(content_items) > 0:
                    return content_items[0]["text"]
            return result_data
        return response_json
    except json.JSONDecodeError:
        return {"error": f"Failed to parse response: {response_text}"}

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="upload_file",
            description="Upload file from Kali to FlareVM",
            inputSchema={
                "type": "object",
                "properties": {
                    "local_path": {"type": "string", "description": "Path on Kali"},
                    "remote_path": {"type": "string", "description": "Destination path on FlareVM"}
                },
                "required": ["local_path", "remote_path"]
            }
        ),
        types.Tool(
            name="download_file",
            description="Download file from FlareVM to Kali",
            inputSchema={
                "type": "object",
                "properties": {
                    "remote_path": {"type": "string", "description": "Path on FlareVM"},
                    "local_path": {"type": "string", "description": "Destination path on Kali"}
                },
                "required": ["remote_path", "local_path"]
            }
        ),
        
        types.Tool(
            name="check_connection",
            description="Check WinRM connection to FlareVM",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        types.Tool(
            name="execute_powershell",
            description="Execute PowerShell command on FlareVM",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string"}
                },
                "required": ["command"]
            }
        ),
        types.Tool(
            name="read_file",
            description="Read file content from FlareVM",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="get_file_hash",
            description="Calculate file hash",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "algorithm": {"type": "string", "enum": ["MD5", "SHA1", "SHA256"], "default": "SHA256"}
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="list_processes",
            description="List running processes",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string"}
                }
            }
        ),
        
        types.Tool(
            name="ida_get_metadata",
            description="Get metadata about binary in IDA",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="ida_list_functions",
            description="List functions in binary",
            inputSchema={
                "type": "object",
                "properties": {
                    "queries": {
                        "type": "array",
                        "description": "Array of query objects with offset/count or address/name filters",
                        "items": {
                            "type": "object",
                            "properties": {
                                "offset": {"type": "integer"},
                                "count": {"type": "integer"}
                            }
                        }
                    }
                },
                "required": ["queries"]
            }
        ),
        types.Tool(
            name="ida_decompile",
            description="Decompile function(s) by start address (hex string, e.g. 0x14001127b)",
            inputSchema={
                "type": "object",
                "properties": {
                    "addrs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Function start addresses to decompile"
                    }
                },
                "required": ["addrs"]
            }
        ),
        types.Tool(
            name="ida_disassemble",
            description="Get assembly for function(s) by start address (hex string, e.g. 0x14001127b)",
            inputSchema={
                "type": "object",
                "properties": {
                    "addrs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Function start addresses to disassemble"
                    }
                },
                "required": ["addrs"]
            }
        ),
        types.Tool(
            name="ida_list_strings",
            description="List strings in binary",
            inputSchema={
                "type": "object",
                "properties": {
                    "queries": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "offset": {"type": "integer"},
                                "count": {"type": "integer"}
                            }
                        }
                    }
                },
                "required": ["queries"]
            }
        ),
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    import traceback
    try:
        # ========== File Transfer ==========
        if name == "upload_file":
            local_path = Path(arguments["local_path"])
            remote_path = arguments["remote_path"]

            # Get file size and calculate hash before transfer
            file_size = local_path.stat().st_size
            with open(local_path, "rb") as f:
                file_content = f.read()
                local_sha256 = hashlib.sha256(file_content).hexdigest()

            status_messages = []
            transfer_method = "WinRM"

            # For large files (>8KB), use SMB. For small files, use WinRM
            if file_size > 8192:
                transfer_method = "SMB"
                status_messages.append(f"File size: {file_size:,} bytes - using SMB transfer")

                # Upload to SMB share using smbclient
                filename = os.path.basename(str(local_path))
                smb_temp_path = f"{SMB_LOCAL_PATH}\\{filename}"

                try:
                    # Use smbclient to upload file
                    smb_cmd = [
                        'smbclient',
                        SMB_SHARE_PATH,
                        '-U', f'{FLAREVM_USER}%{FLAREVM_PASSWORD}',
                        '-c', f'put "{local_path}" "{filename}"'
                    ]

                    status_messages.append("Uploading via SMB...")
                    result = subprocess.run(smb_cmd, capture_output=True, text=True, check=True)
                    status_messages.append("SMB upload complete")

                    # Move file from share to final destination
                    if smb_temp_path != remote_path:
                        move_cmd = f'Move-Item -Path "{smb_temp_path}" -Destination "{remote_path}" -Force'
                        await run_ps_async(move_cmd, timeout=30)
                        status_messages.append(f"Moved to final destination: {remote_path}")

                except subprocess.CalledProcessError as e:
                    return [types.TextContent(type="text", text=f"SMB upload failed: {e.stderr}")]
            else:
                # Small file - use WinRM with base64
                status_messages.append(f"File size: {file_size:,} bytes - using WinRM transfer")
                file_data_b64 = base64.b64encode(file_content).decode('utf-8')

                cmd = f'''
$base64 = @"
{file_data_b64}
"@
$bytes = [System.Convert]::FromBase64String($base64)
[System.IO.File]::WriteAllBytes("{remote_path}", $bytes)
'''
                await run_ps_async(cmd, timeout=30)
                status_messages.append("WinRM upload complete")

            # Verify checksum
            cmd = f'''
$hash = Get-FileHash -Path "{remote_path}" -Algorithm SHA256
$remoteSize = (Get-Item "{remote_path}").Length
@{{
    FileSize = $remoteSize
    SHA256 = $hash.Hash
}} | ConvertTo-Json
'''
            result = await run_ps_async(cmd, timeout=30)
            output = result.std_out.decode('utf-8', errors='replace')

            # Parse and verify checksum
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                remote_info = json.loads(json_match.group())
                remote_sha256 = remote_info['SHA256'].lower()
                remote_size = remote_info['FileSize']

                checksum_match = "✓ VERIFIED" if local_sha256.lower() == remote_sha256 else "✗ MISMATCH"
                size_match = "✓" if file_size == remote_size else "✗"

                status_log = "\n".join(status_messages)

                return [types.TextContent(type="text", text=f'''File uploaded successfully!

Transfer Method: {transfer_method}
{status_log}

Source: {local_path}
Destination: {remote_path}
Size: {file_size:,} bytes {size_match}
Local SHA256:  {local_sha256}
Remote SHA256: {remote_sha256}
Checksum: {checksum_match}
''')]

            return [types.TextContent(type="text", text=f"Uploaded to {remote_path}\n\n{output}")]
        
        elif name == "download_file":
            remote_path = arguments["remote_path"]
            local_path = Path(arguments["local_path"])

            # Download file as base64
            cmd = f'''
$bytes = [System.IO.File]::ReadAllBytes("{remote_path}")
[System.Convert]::ToBase64String($bytes)
'''
            result = await run_ps_async(cmd, timeout=120)
            file_data_b64 = result.std_out.decode('utf-8', errors='replace').strip()

            # Decode and save
            file_data = base64.b64decode(file_data_b64)
            with open(local_path, "wb") as f:
                f.write(file_data)

            return [types.TextContent(type="text", text=f"File downloaded to {local_path}")]
        
        elif name.startswith("ida_"):
            # Map FlareVM tool names to IDA Pro MCP tool names
            ida_tool_mapping = {
                "ida_get_metadata": "idb_meta",
                "ida_list_functions": "list_funcs",
                "ida_decompile_function": "decompile",
                "ida_decompile": "decompile",
                "ida_disassemble_function": "disasm",
                "ida_disassemble": "disasm",
                "ida_list_strings": "strings",
                "ida_set_comment": "set_comments",
                "ida_rename_function": "rename",
            }
            
            ida_method = ida_tool_mapping.get(name)
            if not ida_method:
                return [types.TextContent(type="text", text=f"Unknown IDA tool: {name}")]
            def _normalize_ida_args(method: str, args: dict) -> dict:
                if method in ("decompile", "disasm"):
                    if isinstance(args, dict) and "addrs" in args and isinstance(args["addrs"], list):
                        return {"addrs": args["addrs"]}

                    addrs: list[str] = []
                    if isinstance(args, dict) and "queries" in args and isinstance(args["queries"], list):
                        for q in args["queries"]:
                            if not isinstance(q, dict):
                                continue
                            if "address" in q and isinstance(q["address"], str):
                                addrs.append(q["address"])
                            if "addr" in q and isinstance(q["addr"], str):
                                addrs.append(q["addr"])
                            if "addrs" in q and isinstance(q["addrs"], list):
                                addrs.extend([a for a in q["addrs"] if isinstance(a, str)])

                    if not addrs and isinstance(args, dict) and "address" in args and isinstance(args["address"], str):
                        addrs = [args["address"]]

                    return {"addrs": addrs}

                return args

            ida_args = _normalize_ida_args(ida_method, arguments)
            result = ida_rpc_call(ida_method, ida_args)
            
            if isinstance(result, dict) and "error" in result:
                return [types.TextContent(type="text", text=f"IDA Error: {result['error']}")]
            
            return [types.TextContent(type="text", text=str(result))]
        
        elif name == "check_connection":
            cmd = '''
$info = @{
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    Architecture = $env:PROCESSOR_ARCHITECTURE
    IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"} | Select-Object -First 1).IPAddress
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}
$info | ConvertTo-Json
'''
            result = await run_ps_async(cmd, timeout=30)
            output = result.std_out.decode('utf-8', errors='replace')
            return [types.TextContent(type="text", text=f"✓ Connection successful!\n\n{output}")]

        elif name == "execute_powershell":
            result = await run_ps_async(arguments["command"], timeout=120)
            output = result.std_out.decode('utf-8', errors='replace') if result.std_out else "Done"
            if result.std_err:
                output += f"\n\nErrors:\n{result.std_err.decode('utf-8', errors='replace')}"
            return [types.TextContent(type="text", text=output)]

        elif name == "read_file":
            cmd = f"Get-Content -Path '{arguments['path']}' -Raw"
            result = await run_ps_async(cmd, timeout=60)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "get_file_hash":
            algo = arguments.get("algorithm", "SHA256")
            cmd = f"Get-FileHash -Path '{arguments['path']}' -Algorithm {algo} | ConvertTo-Json"
            result = await run_ps_async(cmd, timeout=30)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]
        
        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        error_details = f"""Error executing tool '{name}':

Exception Type: {type(e).__name__}
Error Message: {str(e)}

Traceback:
{traceback.format_exc()}

Arguments:
{json.dumps(arguments, indent=2)}
"""
        return [types.TextContent(type="text", text=error_details)]

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())