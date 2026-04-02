import sys
import os
sys.path.append(os.path.join(os.getcwd(), "backend", "src"))

try:
    from simulation.mesh_seeder import EnterpriseGraphMeshSeeder
    print("SUCCESS: EnterpriseGraphMeshSeeder imported")
except ImportError as e:
    print(f"FAILED: {e}")
except Exception as e:
    print(f"ERROR: {e}")
