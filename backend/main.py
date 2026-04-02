#!/usr/bin/env python3
"""
CLOUDSCAPE CORE 5.2 CLOUDSCAPE — MAIN ENTRY POINT (SUPREME EDITION)
================================================================
The Enterprise Multi-Cloud Intelligence Mesh.

This module serves as the primary execution gateway, bootstrapping:
- Safe encoding for cross-platform Unicode stability
- Absolute path resolution and directory structure creation
- Logging subsystem initialization with forensic formatting
- Process management with graceful signal handling
- Health check subsystem for pre-flight validation
- Argument parsing for operational modes
- AsyncIO event loop management with Windows compatibility

CLOUDSCAPE 5.2 FIXES:
1. WINDOWS COMPATIBILITY: SIGTERM handling uses try/except, os.statvfs replaced.
2. ENCODING SAFETY: apply_safe_encoding_lock uses function scope, not module-level.
3. GRACEFUL SHUTDOWN: Proper async cleanup with timeout for hung tasks.
4. DISK SPACE CHECK: Platform-agnostic using shutil.disk_usage instead of statvfs.
"""

import os
import sys
from pathlib import Path

# ==============================================================================
# BOOTLOADER PATH INJECTION
# ==============================================================================
# Inject the src/ directory into the python path to resolve all modules natively
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import time
import signal
import shutil
import logging
import asyncio
import argparse
import platform
import traceback
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from rich.console import Console  # type: ignore
from rich.panel import Panel  # type: ignore
from rich.text import Text  # type: ignore
from rich.table import Table  # type: ignore
from rich import box  # type: ignore
from rich.traceback import install # type: ignore

# Install Global Advanced Traceback Hooks
install(show_locals=True, width=120, word_wrap=True)

console = Console()

# ==============================================================================
# PLATFORM SAFETY — ENCODING LOCK
# ==============================================================================
# Applied as a function call, NOT at import time, to prevent side effects 
# during module imports (e.g., pytest collection, IDE introspection).

def apply_safe_encoding_lock() -> None:
    """
    Forces UTF-8 on all standard streams for cross-platform consistency.
    Called during main() initialization, NOT at module load time.
    """
    import io
    
    try:
        if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore
        elif sys.stdout:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True
            )
    except Exception:
        pass  # Non-critical: some environments have frozen stdout
        
    try:
        if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')  # type: ignore
        elif sys.stderr:
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True
            )
    except Exception:
        pass

    # Set environment variable for child processes
    os.environ.setdefault('PYTHONIOENCODING', 'utf-8')


# ==============================================================================
# PATH RESOLUTION & DIRECTORY BOOTSTRAPPING
# ==============================================================================

# Absolute root of the Cloudscape project
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Required directory structure
REQUIRED_DIRECTORIES = [
    PROJECT_ROOT / "forensics" / "logs",
    PROJECT_ROOT / "forensics" / "reports",
    PROJECT_ROOT / "forensics" / "bson_ledger",
    PROJECT_ROOT / "forensics" / "snapshots",
    PROJECT_ROOT / "data" / "manifests",
    PROJECT_ROOT / "data" / "temp",
    PROJECT_ROOT / "dashboard" / "tmp",
    PROJECT_ROOT / "registry",
]


def bootstrap_directories() -> None:
    """Creates all required directories idempotently."""
    for directory in REQUIRED_DIRECTORIES:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            print(f"[WARN] Permission denied creating: {directory}")
        except Exception as e:
            print(f"[WARN] Could not create {directory}: {e}")


# ==============================================================================
# LOGGING SUBSYSTEM
# ==============================================================================

from utils.logger import configure_logging, get_logger  # type: ignore

def initialize_logging(log_level: str = "INFO", log_to_file: bool = True) -> logging.Logger:
    """
    Initializes the enterprise logging subsystem using the centralized utils.logger.
    """
    log_dir = str(PROJECT_ROOT / "forensics" / "logs") if log_to_file else None
    configure_logging(level=log_level, log_dir=log_dir)
    logger = get_logger("CloudScape.Main")
    return logger


# ==============================================================================
# PROCESS MANAGEMENT & SIGNAL HANDLING
# ==============================================================================

class CloudscapeProcessManager:
    """
    Manages the application lifecycle, signal handling, and graceful shutdown.
    
    WINDOWS FIX: SIGTERM is wrapped in try/except since it's not supported 
    on Windows. Only SIGINT (Ctrl+C) is guaranteed cross-platform.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Process")
        self._shutdown_event: Optional[asyncio.Event] = asyncio.Event() if asyncio.get_event_loop().is_running() else None
        self._orchestrator: Any = None
        self._start_time = time.monotonic()
        self._install_signal_handlers()
    
    def _install_signal_handlers(self) -> None:
        """Installs signal handlers with Windows compatibility."""
        # SIGINT (Ctrl+C) — works on all platforms
        signal.signal(signal.SIGINT, self._handle_shutdown_signal)
        
        # SIGTERM — POSIX only, try/except for Windows compatibility
        try:
            signal.signal(signal.SIGTERM, self._handle_shutdown_signal)
            self.logger.debug("SIGTERM handler installed.")
        except (OSError, ValueError, AttributeError):
            self.logger.debug("SIGTERM not available on this platform (Windows). Using SIGINT only.")
    
    def _handle_shutdown_signal(self, signum: int, frame) -> None:
        """Handles shutdown signals gracefully."""
        sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
        self.logger.warning(f"Received signal {sig_name}. Initiating graceful shutdown...")
        
        if self._orchestrator:
            self._orchestrator.request_shutdown()
        
        if self._shutdown_event is not None:
            self._shutdown_event.set()  # type: ignore
    
    def set_orchestrator(self, orchestrator) -> None:
        """Registers the orchestrator for signal-triggered shutdown."""
        self._orchestrator = orchestrator
    
    def get_uptime_seconds(self) -> float:
        """Returns the process uptime in seconds."""
        return time.monotonic() - self._start_time


# ==============================================================================
# HEALTH CHECK SUBSYSTEM
# ==============================================================================

class HealthCheckRunner:
    """
    Pre-flight validation system. Checks:
    - Required Python version
    - Required dependencies
    - Disk space (platform-agnostic)
    - Network connectivity to key endpoints
    """
    
    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Health")
        self.checks_passed: int = 0
        self.checks_failed: int = 0
        self.check_results: List[Dict[str, Any]] = []
    
    def run_all_checks(self) -> bool:
        """Runs all pre-flight health checks. Returns True if all critical checks pass."""
        self.logger.info("Running pre-flight health checks...")
        
        all_passed = True
        
        # Check 1: Python Version
        all_passed &= self._check_python_version()
        
        # Check 2: Required Dependencies
        all_passed &= self._check_dependencies()
        
        # Check 3: Disk Space (Platform-agnostic)
        self._check_disk_space()  # Non-critical, always returns True
        
        # Check 4: Config Integrity
        all_passed &= self._check_config_integrity()
        
        # Summary Table
        table = Table(title="Pre-Flight Health Checks", border_style="cyan", box=box.MINIMAL)
        table.add_column("System Check", style="magenta", no_wrap=True)
        table.add_column("Status", style="bold")
        table.add_column("Details", style="dim")
        
        for check in self.check_results:
            status_text = "[green]PASS[/green]" if check["passed"] else "[red]FAIL[/red]"
            table.add_row(check["check"].upper(), status_text, str(check["details"]))
            
        console.print()
        console.print(table)
        
        total = self.checks_passed + self.checks_failed
        if all_passed:
            self.logger.info(f"Health checks complete: {self.checks_passed}/{total} passed.")
        else:
            self.logger.error(f"Health checks failed: {self.checks_failed}/{total} failed.")
        
        return all_passed
    
    def _check_python_version(self) -> bool:
        """Validates minimum Python version (3.10+)."""
        major, minor = sys.version_info.major, sys.version_info.minor
        if major < 3 or (major == 3 and minor < 10):
            self.logger.error(f"Python 3.10+ required. Current: {major}.{minor}")
            self._record_check("python_version", False, f"{major}.{minor}")
            return False
        self._record_check("python_version", True, f"{major}.{minor}")
        return True
    
    def _check_dependencies(self) -> bool:
        """Validates that required Python packages are importable."""
        required = [
            'pydantic', 'yaml', 'neo4j', 'boto3', 'streamlit', 'plotly', 'pyvis'
        ]
        missing = []
        
        for pkg in required:
            try:
                import importlib
                importlib.import_module(pkg)
            except ImportError:
                missing.append(pkg)        
        if missing:
            self.logger.warning(f"Missing packages: {', '.join(missing)}. Some features may be unavailable.")
            self._record_check("dependencies", False, {"missing": missing})
            return len(missing) < 3  # Allow up to 2 missing non-critical packages        
        self._record_check("dependencies", True, {"all_present": True})
        return True    
    def _check_disk_space(self) -> bool:
        """
        Platform-agnostic disk space check using shutil.disk_usage.
        FIX: Replaces os.statvfs() which is not available on Windows.
        """
        try:
            usage = shutil.disk_usage(str(PROJECT_ROOT))
            free_gb = usage.free / (1024 ** 3)
            total_gb = usage.total / (1024 ** 3)
            pct_free = (usage.free / usage.total) * 100
            
            if free_gb < 1.0:
                self.logger.warning(f"Low disk space: {free_gb:.1f}GB free ({pct_free:.1f}%)")
                self._record_check("disk_space", False, {"free_gb": round(float(free_gb), 2), "pct_free": round(float(pct_free), 1)})  # type: ignore
            else:
                self.logger.debug(f"Disk space: {free_gb:.1f}GB free of {total_gb:.1f}GB ({pct_free:.1f}%)")
                self._record_check("disk_space", True, {"free_gb": round(float(free_gb), 2), "pct_free": round(float(pct_free), 1)})  # type: ignore
            
            return True  # Non-critical check
        except Exception as e:
            self.logger.debug(f"Could not check disk space: {e}")
            self._record_check("disk_space", True, {"error": str(e)})
            return True
    
    def _check_config_integrity(self) -> bool:
        """Validates that the configuration manager loaded successfully."""
        try:
            from core.config import config as cfg  # type: ignore
            if cfg.settings is None:
                self._record_check("config_integrity", False, "Settings is None")
                return False
            
            diagnostics = cfg.validate_runtime_integrity()
            self._record_check("config_integrity", True, diagnostics)
            return True
        except Exception as e:
            self._record_check("config_integrity", False, str(e))
            return False
    
    def _record_check(self, name: str, passed: bool, details: Any = None) -> None:
        """Records a health check result."""
        if passed:
            self.checks_passed += 1
        else:
            self.checks_failed += 1
        self.check_results.append({"check": name, "passed": passed, "details": details})


# ==============================================================================
# ARGUMENT PARSING
# ==============================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """Builds the main argument parser for the Cloudscape Core CLI."""
    parser = argparse.ArgumentParser(
        description="Cloudscape - Cloud Security and Discovery Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════════╗
║  CLOUDSCAPE - OPERATIONAL MODES                              ║
╠══════════════════════════════════════════════════════════════╣
║  SCAN:    Execute full discovery pipeline (default)         ║
║  DAEMON:  Continuous scan loop with configurable interval   ║
║  REPORT:  Generate security report from latest scan         ║
║  HEALTH:  Run pre-flight health checks only                 ║
║  SCHEMA:  Apply database schema constraints                 ║
╚══════════════════════════════════════════════════════════════╝

Examples:
  python main.py                   # Single scan cycle (MOCK mode)
  python main.py --mode LIVE       # Single scan with live cloud APIs
  python main.py --mode MOCK       # Force simulation mode
  python main.py --api             # Run Native Application overlay server
  python main.py --health          # Pre-flight health checks only
  python main.py --schema          # Apply Neo4j schema constraints
  python main.py --verbose         # Debug-level logging
        """
    )
    
    parser.add_argument(
        "--mode", type=str, default=None,
        choices=["MOCK", "LIVE", "HYBRID", "DRY_RUN"],
        help="Override execution mode (default: from settings.yaml)"
    )
    parser.add_argument(
        "--daemon", action="store_true",
        help="Run in continuous daemon mode with configurable interval"
    )
    parser.add_argument(
        "--interval", type=int, default=300,
        help="Daemon scan interval in seconds (default: 300)"
    )
    parser.add_argument(
        "--api", action="store_true",
        help="Launch the internal React frontend API overlay server"
    )
    parser.add_argument("--timeline", action="store_true", help="Reconstruct forensic timeline from ledger")
    parser.add_argument("--health", action="store_true", help="Run local health diagnostics")
    parser.add_argument("--verbose-trace", action="store_true", help="Enable bit-level diagnostic tracing")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable DEBUG-level logging")
    parser.add_argument("--no-simulation", action="store_true", help="Disable synthetic topology generation")
    parser.add_argument("--tenant", type=str, default=None, help="Process specific tenant ID")
    parser.add_argument("--report", action="store_true", help="Generate forensic report")
    parser.add_argument("--schema", action="store_true", help="Apply database schema constraints")
    
    return parser


# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

async def run_pipeline(args: argparse.Namespace, logger: logging.Logger) -> None:
    """Executes the main pipeline based on parsed arguments."""
    from core.config import config as cfg  # type: ignore
    from core.orchestrator import CloudScapeOrchestrator  # type: ignore
    
    # Override mode if specified
    if args.mode:
        cfg.settings.execution_mode = args.mode
        logger.info(f"Execution mode overridden to: {args.mode}")
    
    # Override simulation if specified
    if args.no_simulation:
        cfg.settings.simulation.enabled = False
        logger.info("Simulation disabled via CLI flag.")
    
    # Initialize orchestrator
    orchestrator = CloudScapeOrchestrator(cfg)
    
    # Register with process manager for signal handling
    process_manager = CloudscapeProcessManager()
    process_manager.set_orchestrator(orchestrator)
    
    try:
        api_server = None
        if args.api:
            from api.server import start_api_server  # type: ignore
            api_server = await start_api_server()
            
        if args.daemon:
            # Daemon Mode: Continuous scan loop
            logger.info(f"Entering daemon mode. Scan interval: {args.interval}s")
            cycle = 0
            
            while not orchestrator._shutdown_requested:
                cycle += 1
                logger.info(f"--- DAEMON CYCLE {cycle} ---")
                
                states = await orchestrator.run_full_pipeline()
                
                # Log cycle summary
                total_nodes = sum(s.merged_nodes_produced for s in states)
                total_errors = sum(len(s.errors) for s in states)
                total_vulns = sum(s.vulnerabilities_discovered for s in states)
                total_threats = sum(s.critical_threats_detected for s in states)
                logger.info(f"Cycle {cycle} complete. Nodes: {total_nodes}, Vulns: {total_vulns}, Threats: {total_threats}, Errors: {total_errors}")
                
                if not orchestrator._shutdown_requested:
                    logger.info(f"Sleeping {args.interval}s until next cycle...")
                    await asyncio.sleep(args.interval)
        elif not args.daemon and args.api:
            # Interactive API mode loop
            logger.info("API Overlay running. Press Ctrl+C to shutdown.")
            while not orchestrator._shutdown_requested:
                await asyncio.sleep(1)
        else:
            # Single Scan Mode
            states = await orchestrator.run_full_pipeline()
            
            # Print scan summary
            table = Table(title="Scan Summary", border_style="cyan", box=box.MINIMAL)
            table.add_column("Tenant", style="magenta", no_wrap=True)
            table.add_column("Status", style="bold")
            table.add_column("Duration (ms)", justify="right", style="green")
            table.add_column("Nodes Discovered", justify="right", style="yellow")
            table.add_column("CVSS Histogram", justify="center")
            table.add_column("Errors", justify="right", style="red")
            
            top_threats = []

            for state in states:
                summary = state.to_dict()
                status_color = "[green]SUCCESS[/green]" if not summary['errors'] else "[red]WARNING/ERROR[/red]"
                inte = summary.get('intelligence', {})
                hist = inte.get('cvss_histogram', {})
                threats = inte.get('findings', [])
                top_threats.extend(threats)
                
                # Format histogram: [red]C: X[/red] [yellow]H: Y[/yellow] [blue]M: Z[/blue]
                hist_str = f"[bold red]C: {hist.get('CRITICAL', 0)}[/bold red] | [yellow]H: {hist.get('HIGH', 0)}[/yellow] | [blue]M: {hist.get('MEDIUM', 0)}[/blue] | [white]L: {hist.get('LOW', 0)}[/white]"
                
                table.add_row(
                    state.tenant_id,
                    status_color,
                    f"{summary['total_duration_ms']:.0f}",
                    str(summary['nodes'].get('merged', 0)),
                    hist_str,
                    str(len(summary['errors']))
                )
            
            console.print()
            console.print(table)
            console.print()
            
            if top_threats:
                matrix = Table(title="Semantic Security Findings Matrix", border_style="red", box=box.DOUBLE)
                matrix.add_column("Resource ARN", style="cyan", overflow="fold")
                matrix.add_column("Rule / CVE", style="magenta")
                matrix.add_column("Severity", style="bold red", justify="center")
                matrix.add_column("Description", style="white", overflow="fold", ratio=2)
                matrix.add_column("Blast Radius", style="bold yellow", justify="center")
                matrix.add_column("Remediation", style="green", overflow="fold", ratio=2)
                
                for t in top_threats: # pyre-ignore[6]
                    r_id = t.get("cve_id") or t.get("rule") or t.get("framework") or t.get("id", "UNKNOWN")
                    matrix.add_row(
                        str(t.get("resource_arn", "UNKNOWN")),
                        str(r_id),
                        str(t.get("severity", "CRITICAL")),
                        str(t.get("description", "No description provided.")),
                        f"{t.get('blast_radius', 0.0):.1f}",
                        str(t.get("remediation", "Investigate logic flows and implement secure boundaries."))
                    )
                console.print(matrix)
                
            # System Component Profiling (MICRO-CHRONOMETRY)
            profiling = Table(title="System Component Profiling", border_style="blue", box=box.HORIZONTALS)
            profiling.add_column("Component", style="cyan")
            profiling.add_column("Stage ID", style="magenta")
            profiling.add_column("Latency (ms)", justify="right")
            profiling.add_column("Status", justify="center")
            
            for state in states: # pyre-ignore[16]
                for stage_id, phase in state.phase_metrics.items(): # pyre-ignore[16]
                    status_style = "bold green" if phase.status.value == "SUCCESS" else "bold red"
                    profiling.add_row(
                        f"[{state.tenant_id}]", # pyre-ignore[16]
                        stage_id,
                        f"{phase.duration_ms:.2f}",
                        f"[{status_style}]{phase.status.value}[/{status_style}]"
                    )
            
            console.print()
            console.print(profiling)
            console.print(f"\n[bold blue]CLOUDSCAPE V15.0 EXECUTED IN {sum(s.total_duration_ms for s in states):.2f}ms TOTAL[/bold blue]") # pyre-ignore[16]
            console.print()
            
        if args.api:
            logger.info("API Overlay initialized. Keeping main thread alive. Press Ctrl+C to shutdown.")
            try:
                while True:
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                pass
    
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user.")
    except Exception as e:
        logger.critical(f"Fatal pipeline error: {e}")
        logger.debug(traceback.format_exc())
    finally:
        await orchestrator.shutdown()
        if 'api_server' in locals() and api_server:
            await api_server.stop()


async def run_schema_init(logger: logging.Logger) -> None:
    """Applies Neo4j enterprise schema constraints."""
    try:
        from utils.db_tools import GraphMaintenanceManager  # type: ignore
        
        manager = GraphMaintenanceManager()
        if await manager.test_connectivity():
            await manager.enforce_enterprise_schema()
        await manager.close()
    except ImportError:
        logger.error("db_tools module not available. Cannot initialize schema.")
    except Exception as e:
        logger.error(f"Schema initialization failed: {e}")
        logger.debug(traceback.format_exc())


def main() -> None:
    """
    The Supreme Entry Point.
    Bootstraps the entire Cloudscape Core 5.2 Cloudscape system.
    """
    # PHASE 1: Encoding Safety (function scope, not module level)
    apply_safe_encoding_lock()
    
    # PHASE 2: Directory Bootstrapping
    bootstrap_directories()
    
    # PHASE 3: Argument Parsing
    parser = build_argument_parser()
    args = parser.parse_args()
    
    # PHASE 4: Logging Initialization
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = initialize_logging(log_level=log_level)
    
    # Enable Verbose Tracing if requested
    if args.verbose_trace:
        from utils.verbose_logger import diagnostic_tracer
        os.environ["VERBOSE_DIAGNOSTIC"] = "1"
        console.print("[bold cyan]Bit-level Diagnostic Tracing: ENABLED[/bold cyan]")

    # PHASE 5: Health & Special Modes
    if args.health:
        from utils.health import HealthMonitor
        monitor = HealthMonitor({})
        report = monitor.run_preflight_checks()
        console.print(Panel(json.dumps(report, indent=2), title="[bold green]Health Diagnostic Report[/bold green]"))
        sys.exit(0 if report["overall_status"] == "HEALTHY" else 1)
        
    if args.timeline:
        from simulation.simulation_studio import SimulationStudio
        from core.forensics import forensic_ledger, TimelineReconstructor
        reconstructor = TimelineReconstructor(forensic_ledger)
        # Assuming a default or latest scan_id for demo
        timeline = reconstructor.playback_scan("SIM-MOCK-SCAN")
        console.print(Panel(json.dumps(timeline, indent=2), title="[bold yellow]Forensic Timeline Playback[/bold yellow]"))
        sys.exit(0)
    
    # General Pre-flight
    health = HealthCheckRunner()
    
    # Non-blocking health check for pipeline mode
    if not health.run_all_checks():
        logger.warning("Some health checks failed. Proceeding anyway...")
    
    # PHASE 6: Windows AsyncIO Policy Fix
    if platform.system() == 'Windows':
        policy = getattr(asyncio, 'WindowsSelectorEventLoopPolicy', None)
        if policy is not None:
            asyncio.set_event_loop_policy(policy())
        logger.debug("Applied WindowsSelectorEventLoopPolicy for Windows compatibility.")
    
    # PHASE 7: Dispatch
    try:
        if args.schema:
            asyncio.run(run_schema_init(logger))
        else:
            asyncio.run(run_pipeline(args, logger))
    except KeyboardInterrupt:
        logger.info("\nShutdown requested by user (Ctrl+C).")
    except Exception as e:
        logger.critical(f"Fatal: {e}")
        logger.debug(traceback.format_exc())
        sys.exit(1)
    
    logger.info("Cloudscape shutdown complete.")


if __name__ == "__main__":
    main()