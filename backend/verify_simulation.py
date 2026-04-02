import asyncio
import logging
import sys
import os

# FORCE src to PRECEDENCE
src_path = os.path.join(os.getcwd(), "backend", "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from core.forensics import forensic_ledger # type: ignore
from core.orchestrator import CloudScapeOrchestrator # type: ignore

async def main():
    logging.basicConfig(level=logging.INFO)
    from core.config import config # type: ignore
    orchestrator = CloudScapeOrchestrator(config)
    
    # 1. Run a base mock scan
    print("\nStep 1: Running Base Mock Scan...")
    states = await orchestrator.run_full_pipeline()
    if not states:
        print("No states returned from pipeline. Aborting.")
        return
        
    state = states[0]
    scan_id = state.scan_id
    print(f"Base Scan Complete: {scan_id}")
    
    # 2. Identify a target
    nodes = forensic_ledger.load_latest_state(scan_id)
    if not nodes:
        print(f"No nodes found in ledger for {scan_id}. Check STAGE_4_CONVERGENCE.")
        # Try to list files in scan_dir for debugging
        scan_dir = os.path.join("storage", "forensics", scan_id)
        if os.path.exists(scan_dir):
            print(f"Files in {scan_dir}: {os.listdir(scan_dir)}")
        return
        
    s3_buckets = [n for n in nodes if n.get("service") == "s3"]
    if not s3_buckets:
        print(f"No S3 buckets found among {len(nodes)} nodes. Aborting.")
        return
        
    target_arn = s3_buckets[0]["arn"]
    print(f"Step 2: Simulating Mutation on {target_arn}...")
    
    # 3. Run Simulation
    sim_result = await orchestrator.simulate_security_drift(scan_id, "MAKE_PUBLIC", target_arn)
    
    if "error" in sim_result:
        print(f"SIMULATION ERROR: {sim_result['error']}")
        return

    print("\n=== SIMULATION RESULTS ===")
    print(f"Mutation: {sim_result['mutation_scenario']}")
    print(f"Drift Summary: {sim_result['topological_drift']}")
    
    blast = sim_result.get("predictive_blast_radius", {})
    print(f"\n--- PREDICTIVE BLAST RADIUS ---")
    print(f"Intensity: {blast.get('intensity_score', 0.0)}")
    print(f"Impacted Resources: {blast.get('impacted_count', 0)}")
    print(f"Critical Assets at Risk: {', '.join(blast.get('critical_resources', []))}")
    print(f"Summary: {blast.get('summary', 'No summary.')}")
    
    analysis = sim_result.get("security_analysis", {})
    print(f"\n--- SECURITY FINDINGS ---")
    print(f"Vulnerabilities Found: {analysis.get('vulnerabilities_found', 0)}")
    
    for finding in analysis.get('findings', []):
        print(f"- {finding['description']} (Blast Radius: {finding.get('blast_radius', 0):.2f})")

if __name__ == "__main__":
    asyncio.run(main())
