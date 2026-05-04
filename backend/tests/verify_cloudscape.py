import sys
import os
from pathlib import Path

# Inject backend/src into path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

def test_imports():
    print("[TEST] Verifying core component imports...")
    try:
        from core.config import config # type: ignore
        from core.orchestrator import CloudScapeOrchestrator # type: ignore
        from core.safety_kernel import safety_guard # type: ignore
        from intelligence.risk_scorer import IntelligenceAI_Predictor # type: ignore
        from intelligence.policy_verifier import SAT_SMT_PolicyVerifier # type: ignore
        from intelligence.killchain_mapper import MitreKillChainSynthesizer # type: ignore
        from intelligence.impact_analyzer import ImpactAnalyzer # type: ignore
        
        print("[PASS] All core components imported successfully.")
        return True
    except ImportError as e:
        print(f"[FAIL] Import error: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected error during import: {e}")
        return False

def test_config_initialization():
    print("[TEST] Verifying configuration initialization...")
    try:
        from core.config import config # type: ignore
        if config.settings.app_metadata.name == "Cloudscape":
            print(f"[PASS] Configuration initialized: {config.settings.app_metadata.name} v{config.settings.app_metadata.version}")
            return True
        else:
            print(f"[FAIL] Unexpected app name: {config.settings.app_metadata.name}")
            return False
    except Exception as e:
        print(f"[ERROR] Configuration initialization failed: {e}")
        return False

def main():
    print("=== CLOUDSCAPE VERIFICATION SUITE ===")
    success = True
    success &= test_imports()
    success &= test_config_initialization()
    
    if success:
        print("\n[RESULT] SYSTEM IS READY FOR OPERATIONAL TESTING.")
    else:
        print("\n[RESULT] SYSTEM VERIFICATION FAILED. CHECK LOGS.")
        sys.exit(1)

if __name__ == "__main__":
    main()
