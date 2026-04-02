import sys
import os
from pathlib import Path
from typing import Dict, Any

import pytest # type: ignore

# Inject backend/src into path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.config import TenantConfig, TenantCredentials # type: ignore
from simulation.state_factory import StateFactory # type: ignore
from simulation.mesh_seeder import EnterpriseGraphMeshSeeder # type: ignore

@pytest.fixture
def dummy_tenant() -> TenantConfig:
    return TenantConfig(
        id="test-tenant-01",
        description="A tenant for schema validation tests",
        credentials=TenantCredentials(
            aws_account_id="111122223333",
            aws_access_key_id="mock_access",
            aws_secret_access_key="mock_secret",
            azure_subscription_id="00000000-0000-0000-0000-000000000000",
            azure_tenant_id="tenant-id",
            azure_client_id="client-id",
            azure_client_secret="client-secret"
        )
    )

def test_simulation_node_payload_schema(dummy_tenant: TenantConfig):
    """
    Strict validation of the mock nodes to ensure they conform 
    perfectly to the expected structural schema used by discovery engines.
    """
    factory = StateFactory()
    nodes = factory.produce_full_topology(dummy_tenant)
    
    # Verify nodes were generated
    assert len(nodes) > 0, "StateFactory failed to produce any nodes"
    
    for node in nodes:
        # Check required top-level keys
        assert "id" in node, f"Node missing 'id': {node}"
        assert "arn" in node, f"Node missing 'arn': {node}"
        assert "provider" in node, f"Node missing 'provider': {node}"
        assert "service" in node, f"Node missing 'service': {node}"
        assert "type" in node, f"Node missing 'type': {node}"
        assert "name" in node, f"Node missing 'name': {node}"
        assert "region" in node, f"Node missing 'region': {node}"
        
        # Check inner structures
        assert isinstance(node.get("metadata"), dict), f"'metadata' must be a dict: {node}"
        assert isinstance(node.get("tags"), dict), f"'tags' must be a dict: {node}"
        assert isinstance(node.get("metrics"), dict), f"'metrics' must be a dict: {node}"
        assert isinstance(node.get("relationships"), list), f"'relationships' must be a list: {node}"
        
        # Provider specific checks
        assert node["provider"] in ("AWS", "AZURE"), f"Invalid provider {node['provider']}"
        
        # Ensure tags are formatted like standard boto3/Azure responses
        assert "Environment" in node["tags"], "Required 'Environment' tag missing"

def test_deterministic_kill_chain_structure(dummy_tenant: TenantConfig):
    """
    Validates that the generated kill chains correctly map 
    to tracking manifests for the Risk Scorer engines.
    """
    factory = StateFactory()
    nodes = factory.produce_full_topology(dummy_tenant)
    manifests = factory.kill_chain_manifests
    
    assert len(manifests) > 0, "No kill chain manifests were generated"
    
    for manifest in manifests:
        assert manifest.vector != ""
        assert manifest.entry_point_arn != ""
        assert len(manifest.hop_arns) == manifest.hop_count
        assert len(manifest.mitre_techniques) > 0
        
def test_mesh_seeder_ingestion_compatibility(dummy_tenant: TenantConfig):
    """
    Ensures that the output of StateFactory can be successfully parsed 
    and seeded into graph relationships by EnterpriseGraphMeshSeeder without crashing.
    """
    factory = StateFactory()
    nodes = factory.produce_full_topology(dummy_tenant)
    
    seeder = EnterpriseGraphMeshSeeder()
    
    metrics = seeder.ingest_mesh(nodes, tenant_id=dummy_tenant.id)
    assert metrics.nodes_created == len(nodes)
    assert not metrics.errors, f"Mesh seeder encountered errors with mock nodes: {metrics.errors}"
