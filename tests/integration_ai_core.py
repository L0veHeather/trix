#!/usr/bin/env python3
"""Real Integration Test for AI-Native Core.

This test actually calls the DeepSeek API and scans a real target.
NOT a mock test - requires valid API key and network access.

Target: http://ruzhu.icu/
"""

import asyncio
import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("IntegrationTest")
logging.getLogger("trix").setLevel(logging.DEBUG)

# ============================================================
# Environment Configuration
# ============================================================
# DeepSeek API Key (from environment)
if not os.environ.get("DEEPSEEK_API_KEY"):
    print("❌ ERROR: DEEPSEEK_API_KEY environment variable not set!")
    print("   Usage: DEEPSEEK_API_KEY=sk-xxx python tests/integration_ai_core.py")
    sys.exit(1)

# Configure LiteLLM for DeepSeek
os.environ["LITELLM_MODEL"] = "deepseek/deepseek-chat"

# ============================================================
# Imports
# ============================================================
from trix.engine.scan_engine import ScanEngine, ScanConfig, ScanStatus
from trix.plugins.base import ScanPhase
from trix.engine.event_bus import EventType, Event


async def run_real_scan():
    """Run a real scan against the target."""
    
    target = "http://ruzhu.icu/"
    logger.info("=" * 60)
    logger.info("🚀 Real Integration Test - AI-Native Core")
    logger.info(f"   Target: {target}")
    logger.info(f"   API: DeepSeek (deepseek-chat)")
    logger.info("=" * 60)
    
    # Initialize Engine
    engine = ScanEngine()
    await engine.initialize()
    logger.info("✅ ScanEngine initialized")
    
    # Capture events
    events = []
    
    async def capture_event(event: Event):
        if event.type == EventType.VULNERABILITY_FOUND:
            logger.info(f"🔥 VULNERABILITY FOUND: {event.data.get('vuln_type')} @ {event.data.get('target')}")
            events.append(event)
    
    # Register AI-compatible SQLi plugin
    from trix.plugins.vulns.sqli import sqli_plugin
    engine._registry._plugins[sqli_plugin.name] = sqli_plugin
    logger.info(f"✅ Registered AI-compatible plugin: {sqli_plugin.name}")
    
    engine._event_bus.subscribe(EventType.VULNERABILITY_FOUND, capture_event)
    
    # Configure scan - use AI-compatible plugin
    config = ScanConfig(
        target=target,
        phases=[ScanPhase.VULNERABILITY_SCAN],
        plugins=["sqli_detector"],  # AI-compatible vulnerability detection
    )
    
    # Start scan
    logger.info(f"🔍 Starting scan of {target}...")
    scan_id = await engine.start_scan(config)
    logger.info(f"   Scan ID: {scan_id}")
    
    # Wait for completion (with timeout)
    timeout = 300  # 5 minutes max
    for i in range(timeout):
        if i % 30 == 0:
            logger.info(f"⏳ Scan running... ({i}s elapsed)")
        
        state = engine._scans.get(scan_id)
        if state and state.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            break
        await asyncio.sleep(1)
    
    # Results
    state = engine._scans.get(scan_id)
    logger.info("=" * 60)
    
    if state.status == ScanStatus.COMPLETED:
        logger.info("✅ Scan COMPLETED!")
    elif state.status == ScanStatus.FAILED:
        logger.info(f"❌ Scan FAILED: {state.error}")
    else:
        logger.info(f"⚠️ Scan ended with status: {state.status}")
    
    logger.info(f"   Vulnerabilities found: {len(events)}")
    
    for i, event in enumerate(events, 1):
        logger.info(f"   [{i}] {event.data.get('vuln_type')}: {event.data.get('target')}")
        if event.data.get('title'):
            logger.info(f"       Title: {event.data.get('title')}")
        if event.data.get('confidence_score'):
            logger.info(f"       Confidence: {event.data.get('confidence_score'):.0%}")
    
    logger.info("=" * 60)
    
    # Cleanup
    await engine.shutdown()
    
    return len(events) > 0


if __name__ == "__main__":
    success = asyncio.run(run_real_scan())
    
    if success:
        print("\n✅ Integration test PASSED - Vulnerabilities detected!")
    else:
        print("\n⚠️ Integration test completed - No vulnerabilities found")
        print("   (This may be normal if the target is secure)")
