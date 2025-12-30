
import asyncio
import shutil
import json

async def run_httpx():
    httpx_path = shutil.which("httpx")
    if not httpx_path:
        print("httpx not found")
        return

    cmd = [httpx_path, "-u", "https://example.com", "-json", "-silent"]
    print(f"Running: {' '.join(cmd)}")
    
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    
    stdout, stderr = await process.communicate()
    print(f"Return code: {process.returncode}")
    print(f"Stdout: {stdout.decode()}")
    print(f"Stderr: {stderr.decode()}")

if __name__ == "__main__":
    asyncio.run(run_httpx())
