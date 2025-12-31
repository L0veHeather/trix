
import sys
import os
import asyncio

# Add project root to path
sys.path.insert(0, os.path.abspath(os.getcwd()))

try:
    print("Importing trix.plugins.vulns...")
    import trix.plugins.vulns
    print("OK")
    
    print("Importing trix.engine.scan_engine...")
    from trix.engine.scan_engine import ScanEngine
    print("OK")
    
    print("Importing trix.models.phase...")
    from trix.models.phase import PhaseConfig, PhaseResult
    print("OK")
    
    print("Importing trix.engine.result_collector...")
    from trix.engine.result_collector import ResultCollector
    print("OK")
    
    print("Importing trix.core.llm_controller...")
    from trix.core.llm_controller import ScanController
    print("OK")
    
    print("Importing trix.core.concurrent_executor...")
    from trix.core.concurrent_executor import ConcurrentExecutor
    print("OK")
    
    print("Importing trix.brain.openai_judge...")
    from trix.brain.openai_judge import OpenAIJudge
    print("OK")
    
    print("ALL MODULES IMPORTED SUCCESSFULLY")

except ImportError as e:
    print(f"ImportError: {e}")
    sys.exit(1)
except SyntaxError as e:
    print(f"SyntaxError: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
