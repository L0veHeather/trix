
import asyncio
import logging
import sys
from trix.plugins.registry import PluginRegistry

# Context manager for logging
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

async def main():
    print("Starting registry initialization check...")
    registry = PluginRegistry()
    try:
        result = await asyncio.wait_for(registry.initialize(), timeout=10.0)
        print(f"Registry initialized. Valid: {len(result.valid)}, Invalid: {len(result.invalid)}")
        for p in result.valid:
            plugin = registry.get_plugin(p)
            print(f"Plugin {p}: Status={plugin.status}, Enabled={plugin.config.enabled}")
    except asyncio.TimeoutError:
        print("Registry initialization TIMED OUT!")
    except Exception as e:
        print(f"Registry initialization FAILED: {e}")

if __name__ == "__main__":
    asyncio.run(main())
