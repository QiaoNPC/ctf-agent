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
from datetime import datetime, timedelta
import random
import string

FLAREVM_HOST = "flarevm"
FLAREVM_USER = "kali"
FLAREVM_PASSWORD = "kali"

SMB_SHARE_NAME = "KaliShare"
SMB_SHARE_PATH = f"//{FLAREVM_HOST}/{SMB_SHARE_NAME}"
SMB_LOCAL_PATH = "C:\\Share"

session = winrm.Session(
    FLAREVM_HOST,
    auth=(FLAREVM_USER, FLAREVM_PASSWORD),
    transport="plaintext"
)

executor = ThreadPoolExecutor(max_workers=4)
app = Server("flarevm-remote")


def _first_json_object(text: str):
    if not text:
        return None
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        try:
            return json.loads(text)
        except Exception:
            pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


async def run_ps_async(command: str, timeout: int = 120):
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
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": method,
            "arguments": params or {}
        },
        "id": 1
    }

    ps_script = f"""
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
"""
    result = session.run_ps(ps_script)
    response_text = result.std_out.decode("utf-8", errors="replace").strip()

    try:
        response_json = json.loads(response_text)
        if "error" in response_json:
            return {"error": response_json["error"].get("message", str(response_json["error"]))}

        if "result" in response_json:
            result_data = response_json["result"]
            if isinstance(result_data, dict) and "content" in result_data:
                content_items = result_data["content"]
                if content_items and len(content_items) > 0:
                    return content_items[0].get("text", "")
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
            name="execute_desktop_cmd",
            description="Run a command interactively in the logged-on desktop session via a one-shot scheduled task (useful for GUI/console-only tools). Output is written to a log file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command to run (e.g. x64dbg.exe C:\\path\\file.exe)"},
                    "working_dir": {"type": "string", "description": "Working directory (optional)", "default": "C:\\Users\\kali\\Desktop"},
                    "wait": {"type": "boolean", "description": "Wait for task completion (best-effort)", "default": False},
                    "timeout": {"type": "integer", "description": "Wait timeout seconds if wait=true", "default": 90}
                },
                "required": ["command"]
            }
        ),
        types.Tool(
            name="check_connection",
            description="Check WinRM connection to FlareVM",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="execute_powershell",
            description="Execute PowerShell command on FlareVM",
            inputSchema={
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"]
            }
        ),
        types.Tool(
            name="read_file",
            description="Read file content from FlareVM",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
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
            inputSchema={"type": "object", "properties": {"filter": {"type": "string"}}}
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
                        "items": {"type": "object", "properties": {"offset": {"type": "integer"}, "count": {"type": "integer"}}}
                    }
                },
                "required": ["queries"]
            }
        ),
        types.Tool(
            name="ida_decompile",
            description="Decompile function(s) by start address (hex string)",
            inputSchema={
                "type": "object",
                "properties": {"addrs": {"type": "array", "items": {"type": "string"}}},
                "required": ["addrs"]
            }
        ),
        types.Tool(
            name="ida_disassemble",
            description="Get assembly for function(s) by start address (hex string)",
            inputSchema={
                "type": "object",
                "properties": {"addrs": {"type": "array", "items": {"type": "string"}}},
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
                        "items": {"type": "object", "properties": {"offset": {"type": "integer"}, "count": {"type": "integer"}}}
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
        if name == "upload_file":
            local_path = Path(arguments["local_path"])
            remote_path = arguments["remote_path"]

            file_size = local_path.stat().st_size
            with open(local_path, "rb") as f:
                file_content = f.read()
                local_sha256 = hashlib.sha256(file_content).hexdigest()

            status_messages = []
            transfer_method = "SMB"
            
            # Always use SMB transfer for all file sizes (more reliable than WinRM)
            status_messages.append(f"File size: {file_size:,} bytes - using SMB transfer")

            filename = os.path.basename(str(local_path))
            smb_temp_path = f"{SMB_LOCAL_PATH}\\{filename}"

            try:
                smb_cmd = [
                    "smbclient",
                    SMB_SHARE_PATH,
                    "-U", f"{FLAREVM_USER}%{FLAREVM_PASSWORD}",
                    "-c", f'put "{local_path}" "{filename}"'
                ]

                status_messages.append("Uploading via SMB...")
                subprocess.run(smb_cmd, capture_output=True, text=True, check=True)
                status_messages.append("SMB upload complete")

                if smb_temp_path != remote_path:
                    move_cmd = f'''
$dstDir = Split-Path -Parent "{remote_path}"
if ($dstDir -and -not (Test-Path $dstDir)) {{ New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }}
Move-Item -Path "{smb_temp_path}" -Destination "{remote_path}" -Force
'''
                    await run_ps_async(move_cmd, timeout=60)
                    status_messages.append(f"Moved to final destination: {remote_path}")

            except subprocess.CalledProcessError as e:
                return [types.TextContent(type="text", text=f"SMB upload failed:\n{e.stderr}")]

            verify_cmd = f'''
try {{
  $ErrorActionPreference = "Stop"
  $hash = Get-FileHash -Path "{remote_path}" -Algorithm SHA256
  $remoteSize = (Get-Item "{remote_path}").Length
  @{{
    Ok = $true
    FileSize = $remoteSize
    SHA256 = $hash.Hash
  }} | ConvertTo-Json -Compress
}} catch {{
  @{{
    Ok = $false
    Error = $_.Exception.Message
    Path = "{remote_path}"
  }} | ConvertTo-Json -Compress
}}
'''
            result = await run_ps_async(verify_cmd, timeout=60)
            stdout = result.std_out.decode("utf-8", errors="replace").strip() if result.std_out else ""
            stderr = result.std_err.decode("utf-8", errors="replace").strip() if result.std_err else ""

            remote_info = _first_json_object(stdout)
            if not remote_info:
                status_log = "\n".join(status_messages)
                return [types.TextContent(
                    type="text",
                    text=f"""File uploaded, but checksum verification output was not parseable.

Transfer Method: {transfer_method}
{status_log}

Destination: {remote_path}

STDERR:
{stderr}

STDOUT:
{stdout}
"""
                )]

            if not remote_info.get("Ok", True):
                status_log = "\n".join(status_messages)
                return [types.TextContent(
                    type="text",
                    text=f"""File uploaded, but checksum verification failed.

Transfer Method: {transfer_method}
{status_log}

Destination: {remote_path}
VerifyError: {remote_info.get("Error")}

STDERR:
{stderr}

STDOUT:
{stdout}
"""
                )]

            remote_sha256_raw = remote_info.get("SHA256")
            remote_size = remote_info.get("FileSize")

            if not isinstance(remote_sha256_raw, str) or not remote_sha256_raw.strip():
                status_log = "\n".join(status_messages)
                return [types.TextContent(
                    type="text",
                    text=f"""File uploaded, but remote SHA256 was empty.

Transfer Method: {transfer_method}
{status_log}

Destination: {remote_path}

RemoteInfo:
{json.dumps(remote_info, indent=2)}

STDERR:
{stderr}

STDOUT:
{stdout}
"""
                )]

            remote_sha256 = remote_sha256_raw.lower()
            checksum_match = "✓ VERIFIED" if local_sha256.lower() == remote_sha256 else "✗ MISMATCH"
            size_match = "✓" if file_size == remote_size else "✗"

            status_log = "\n".join(status_messages)
            return [types.TextContent(
                type="text",
                text=f"""File uploaded successfully!

Transfer Method: {transfer_method}
{status_log}

Source: {local_path}
Destination: {remote_path}
Size: {file_size:,} bytes {size_match}
Local SHA256:  {local_sha256}
Remote SHA256: {remote_sha256}
Checksum: {checksum_match}
"""
            )]

        elif name == "download_file":
            remote_path = arguments["remote_path"]
            local_path = Path(arguments["local_path"])

            cmd = f'''
$bytes = [System.IO.File]::ReadAllBytes("{remote_path}")
[System.Convert]::ToBase64String($bytes)
'''
            result = await run_ps_async(cmd, timeout=180)
            file_data_b64 = result.std_out.decode("utf-8", errors="replace").strip()
            file_data = base64.b64decode(file_data_b64)
            with open(local_path, "wb") as f:
                f.write(file_data)
            return [types.TextContent(type="text", text=f"File downloaded to {local_path}")]

        elif name == "execute_desktop_cmd":
            command = arguments["command"]
            working_dir = arguments.get("working_dir", "C:\\Users\\kali\\Desktop")
            wait = bool(arguments.get("wait", False))
            timeout = int(arguments.get("timeout", 90))

            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            task_name = f"MCP_Desktop_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{rand}"
            log_dir = "C:\\temp\\mcp_desktop"
            log_path = f"{log_dir}\\{task_name}.log"

            start_time = (datetime.now() + timedelta(minutes=1)).strftime("%H:%M")

            ps = f'''
$ErrorActionPreference = "Continue"
if (-not (Test-Path "{log_dir}")) {{ New-Item -ItemType Directory -Path "{log_dir}" -Force | Out-Null }}

$cmd = 'cmd.exe /c cd /d "{working_dir}" ^& {command} ^> "{log_path}" 2^>^&1'
$tn  = "{task_name}"
$st  = "{start_time}"

schtasks /Delete /TN $tn /F 2>$null | Out-Null
schtasks /Create /TN $tn /TR $cmd /SC ONCE /ST $st /RL HIGHEST /RU "{FLAREVM_USER}" /RP "{FLAREVM_PASSWORD}" /IT /F | Out-String
schtasks /Run /TN $tn | Out-String

@{{
  TaskName = $tn
  LogPath  = "{log_path}"
  Note     = "Requires an interactive logged-on session (RDP/console) for /IT to display a window."
}} | ConvertTo-Json -Compress
'''
            result = await run_ps_async(ps, timeout=60)
            stdout = result.std_out.decode("utf-8", errors="replace").strip() if result.std_out else ""
            stderr = result.std_err.decode("utf-8", errors="replace").strip() if result.std_err else ""

            info = _first_json_object(stdout)
            if not info:
                return [types.TextContent(
                    type="text",
                    text=f"Started desktop task (unparsed output).\n\nSTDERR:\n{stderr}\n\nSTDOUT:\n{stdout}"
                )]

            if wait:
                poll_ps = f'''
$tn = "{task_name}"
$deadline = (Get-Date).AddSeconds({timeout})
$status = $null
while ((Get-Date) -lt $deadline) {{
  $q = schtasks /Query /TN $tn /FO LIST /V 2>&1 | Out-String
  if ($q -match "Status:\\s+(\\S+)") {{
    $status = $Matches[1]
  }}
  if ($status -and $status -ne "Running") {{ break }}
  Start-Sleep -Seconds 2
}}
@{{
  TaskName = "{task_name}"
  Status   = $status
  LogPath  = "{log_path}"
  Query    = $q
}} | ConvertTo-Json -Compress
'''
                pr = await run_ps_async(poll_ps, timeout=timeout + 20)
                pstdout = pr.std_out.decode("utf-8", errors="replace").strip() if pr.std_out else ""
                pobj = _first_json_object(pstdout) or {"TaskName": task_name, "LogPath": log_path, "Raw": pstdout}
                return [types.TextContent(type="text", text=json.dumps(pobj, indent=2))]

            return [types.TextContent(type="text", text=json.dumps(info, indent=2))]

        elif name.startswith("ida_"):
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
            result = await run_ps_async(cmd, timeout=60)
            output = result.std_out.decode("utf-8", errors="replace")
            return [types.TextContent(type="text", text=f"✓ Connection successful!\n\n{output}")]

        elif name == "execute_powershell":
            result = await run_ps_async(arguments["command"], timeout=240)
            output = result.std_out.decode("utf-8", errors="replace") if result.std_out else "Done"
            if result.std_err:
                output += f"\n\nErrors:\n{result.std_err.decode('utf-8', errors='replace')}"
            return [types.TextContent(type="text", text=output)]

        elif name == "read_file":
            cmd = f"Get-Content -Path '{arguments['path']}' -Raw"
            result = await run_ps_async(cmd, timeout=120)
            return [types.TextContent(type="text", text=result.std_out.decode("utf-8", errors="replace"))]

        elif name == "get_file_hash":
            algo = arguments.get("algorithm", "SHA256")
            cmd = f"Get-FileHash -Path '{arguments['path']}' -Algorithm {algo} | ConvertTo-Json"
            result = await run_ps_async(cmd, timeout=120)
            return [types.TextContent(type="text", text=result.std_out.decode("utf-8", errors="replace"))]

        elif name == "list_processes":
            filter_str = arguments.get("filter", "")
            filter_clause = f"| Where-Object {{$_.Name -like '*{filter_str}*'}}" if filter_str else ""
            cmd = f"Get-Process {filter_clause} | Select-Object Id, Name, CPU, WS, Path | ConvertTo-Json"
            result = await run_ps_async(cmd, timeout=120)
            return [types.TextContent(type="text", text=result.std_out.decode("utf-8", errors="replace"))]

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