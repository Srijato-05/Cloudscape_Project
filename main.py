import os
import sys
import time
import signal
import asyncio
import logging
import argparse
import platform

# ==============================================================================
# ENTERPRISE PRE-FLIGHT CHECKS
# ==============================================================================
# Ensure we are running a supported Python version before importing complex modules
if sys.version_info < (3, 9):
    sys.exit("FATAL: Project Cloudscape Nexus v4.0 requires Python 3.9 or higher.")

# ==============================================================================
# CORE SYSTEM IMPORTS
# ==============================================================================
# We import configuration first to bootstrap the logging singleton
from core.config import config
from core.orchestrator import CloudscapeOrchestrator

logger = logging.getLogger("Cloudscape.CLI")

# ==============================================================================
# ENTERPRISE EVENT LOOP OPTIMIZATION
# ==============================================================================
def optimize_event_loop():
    """
    Conditionally injects 'uvloop' if running on Linux/macOS.
    uvloop is written in Cypher/C and makes AsyncIO 2-4x faster, which is 
    critical for handling 10,000+ simultaneous API socket connections.
    Windows does not support uvloop, so we gracefully fall back to the native loop.
    """
    if platform.system() != "Windows":
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            logger.info("Platform optimization applied: uvloop EventLoopPolicy injected.")
        except ImportError:
            logger.warning("uvloop not installed. Using standard asyncio event loop.")
    else:
        # Windows specific optimization for asyncio subprocesses
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        logger.debug("Windows platform detected: standard EventLoopPolicy applied.")

# ==============================================================================
# GRACEFUL SHUTDOWN HANDLER
# ==============================================================================
def handle_sigint(sig, frame):
    """
    Catches OS-level termination signals (Ctrl+C, Docker Stop).
    Prevents database corruption by giving the Orchestrator a moment to 
    finish its current Cypher UNWIND transaction before exiting.
    """
    logger.critical(f"\n[!] RECEIVED TERMINATION SIGNAL ({sig}). Initiating graceful shutdown...")
    logger.critical("[!] Please wait while database connection pools are closed. Do not force quit.")
    
    # We cancel all running tasks in the current loop
    loop = asyncio.get_event_loop()
    for task in asyncio.all_tasks(loop=loop):
        task.cancel()
    
    # The loop's exception handler will catch the CancelledError and exit cleanly
    pass 

# ==============================================================================
# CLI DEFINITION & ASCII ART
# ==============================================================================
def print_banner():
    banner = f"""
    ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
    ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
    ██║     ██║     ██║   ██║██║   ██║██║  ██║███████╗██║     ███████║██████╔╝█████╗  
    ██║     ██║     ██║   ██║██║   ██║██║  ██║╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝  
    ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝███████║╚██████╗██║  ██║██║     ███████╗
     ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝
    ==================================================================================
    NEXUS ARCHITECTURE v{config.settings.app_metadata.version} | MULTI-CLOUD GRAPH INTELLIGENCE FABRIC
    ==================================================================================
    """
    print(banner)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Cloudscape Nexus v4.0 - Enterprise Cloud Graph Discovery Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "--scan", 
        action="store_true", 
        help="Initiates a full discovery and ingestion scan across all configured tenants."
    )
    
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Overrides settings.yaml to enable verbose DEBUG logging for troubleshooting."
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version=f"Cloudscape Nexus v{config.settings.app_metadata.version}"
    )

    return parser.parse_args()

# ==============================================================================
# ASYNC MAIN ENTRY POINT
# ==============================================================================
async def execute_application(args: argparse.Namespace):
    """
    The asynchronous shell that instantiates the Orchestrator.
    Wrapped in a massive try/catch to ensure the CLI always returns a standard 
    POSIX exit code (0 for success, 1 for failure).
    """
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("DEBUG logging forcefully enabled via CLI override.")

    if not args.scan:
        logger.info("No execution flag provided. Use --scan to begin discovery, or --help for options.")
        return

    orchestrator = None
    try:
        orchestrator = CloudscapeOrchestrator()
        await orchestrator.execute_global_scan()
        
    except asyncio.CancelledError:
        logger.warning("Application execution was manually cancelled via OS signal.")
    except Exception as e:
        logger.critical(f"A catastrophic failure occurred in the Application Core: {e}", exc_info=True)
        sys.exit(1)

# ==============================================================================
# SYNCHRONOUS BOOTSTRAPPER
# ==============================================================================
if __name__ == "__main__":
    # 1. Catch OS Signals for Graceful Shutdown
    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    # 2. Parse CLI Args & Print UI
    args = parse_arguments()
    if len(sys.argv) > 1:
        print_banner()

    # 3. Apply High-Performance Event Loop
    optimize_event_loop()

    # 4. Ignite the Engine
    try:
        asyncio.run(execute_application(args))
        logger.info("Cloudscape CLI execution completed successfully. Exiting (0).")
        sys.exit(0)
    except KeyboardInterrupt:
        # Failsafe catch if signal handler doesn't trap it in time
        print("\n[!] Force quit detected. Exiting.")
        sys.exit(1)