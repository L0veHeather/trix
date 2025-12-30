
import asyncio
from trix.plugins.urlfinder.plugin import URLFinderPlugin

async def check():
    plugin = URLFinderPlugin()
    is_installed = await plugin.check_installed()
    exe_path = plugin._get_executable()
    print(f"Installed: {is_installed}")
    print(f"Path: {exe_path}")

if __name__ == "__main__":
    asyncio.run(check())
