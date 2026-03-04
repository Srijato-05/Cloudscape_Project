import os
import asyncio
import logging
import importlib
import traceback
import uuid
from typing import Any, Dict, List

from engines.base_engine import BaseDiscoveryEngine
from core.config import config, TenantConfig

# ==============================================================================
# AZURE ENTERPRISE DISCOVERY ENGINE (NEXUS 5.0 AETHER)
# ==============================================================================
# Environmentally Aware: Automatically splits logic between Real Azure ARM 
# (Control Plane) and Local Azurite Mesh (Data Plane).
# Implements 'Hybrid Overlays' to generate synthetic Management Plane assets
# when running against a local Data Plane simulator.
# ==============================================================================

class AzureEngine(BaseDiscoveryEngine):
    def __init__(self, tenant: TenantConfig):
        super().__init__(tenant)
        self.logger = logging.getLogger(f"Cloudscape.Engines.Azure.[{self.tenant.id}]")
        self.credential = self.get_azure_credential()
        self.subscription_id = self.tenant.credentials.azure_subscription_id
        
        # [AETHER SECURITY BYPASS]
        if self.is_mocked:
            self._disable_azure_tls_enforcement()
            # Azurite uses a well-known master key for local data plane access
            self.azurite_conn_str = (
                f"DefaultEndpointsProtocol=http;"
                f"AccountName=devstoreaccount1;"
                f"AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
                f"BlobEndpoint={self.mock_endpoint}/devstoreaccount1;"
            )

    def _disable_azure_tls_enforcement(self):
        """Neutralizes the Azure SDK's strict TLS enforcement for local testing."""
        self.logger.debug(f"[{self.tenant.id}] Injecting Azure TLS Policy Bypass for Local Mesh...")
        try:
            from azure.core.pipeline.policies import BearerTokenCredentialPolicy
            BearerTokenCredentialPolicy._enforce_https = lambda self, request: None
            os.environ["AZURE_CORE_DISABLE_HTTPS_ENFORCEMENT"] = "True"
        except ImportError:
            pass

    # ==========================================================================
    # AUTHENTICATION & CONNECTIVITY (SPLIT BRAIN)
    # ==========================================================================

    async def test_connection(self) -> bool:
        """
        Validates Azure connectivity. 
        If Local: Tests Data Plane (Azurite Blob Service).
        If Prod: Tests Control Plane (Azure Resource Manager).
        """
        self.logger.info("Testing Azure Authentication & Subscription Access...")
        try:
            if self.is_mocked:
                # LOCAL MESH: Test Azurite Data Plane
                BlobServiceClient = getattr(importlib.import_module("azure.storage.blob"), "BlobServiceClient")
                blob_client = BlobServiceClient.from_connection_string(self.azurite_conn_str)
                
                await self.execute_with_backoff(asyncio.to_thread, blob_client.get_service_properties)
                self.logger.debug(f"[{self.tenant.id}] Azurite Local Mesh Auth Success.")
                return True
            else:
                # PROD MESH: Test Azure Resource Manager
                ResourceManagementClient = getattr(importlib.import_module("azure.mgmt.resource"), "ResourceManagementClient")
                rm_client = ResourceManagementClient(credential=self.credential, subscription_id=self.subscription_id)
                
                await self.execute_with_backoff(asyncio.to_thread, lambda: list(rm_client.resource_groups.list()))
                self.logger.debug(f"[{self.tenant.id}] Azure Auth Success for Subscription: {self.subscription_id}")
                return True
                
        except Exception as e:
            err_str = str(e).lower()
            if "authentication failed" in err_str or "unauthorized" in err_str:
                self.logger.error(f"Azure Authentication failed. Invalid Tenant/Client ID: {e}")
            elif "connection refused" in err_str:
                self.logger.error(f"Azurite container is unreachable. Is port 10000 open? {e}")
            else:
                self.logger.critical(f"Unexpected connection error during Azure init: {e}\n{traceback.format_exc()}")
            return False

    # ==========================================================================
    # SERVICE EXTRACTION PIPELINES (HYBRID OVERLAY ARCHITECTURE)
    # ==========================================================================

    async def _extract_storage_accounts(self, baseline_risk: float) -> List[Dict]:
        """
        Extracts Storage assets. 
        If Local: Extracts actual Live Azurite Blob Containers from the Docker mesh.
        If Prod: Extracts Storage Accounts via ARM.
        """
        payloads = []
        try:
            if self.is_mocked:
                # LIVE MESH EXTRACTION: Pull actual Containers seeded in Azurite
                BlobServiceClient = getattr(importlib.import_module("azure.storage.blob"), "BlobServiceClient")
                blob_client = BlobServiceClient.from_connection_string(self.azurite_conn_str)
                
                containers = await self.execute_with_backoff(
                    asyncio.to_thread, lambda: list(blob_client.list_containers(include_metadata=True))
                )
                
                for container in containers:
                    c_name = container.get("name")
                    arn = f"/subscriptions/mock-sub/resourceGroups/local-rg/providers/Microsoft.Storage/storageAccounts/devstoreaccount1/blobServices/default/containers/{c_name}"
                    
                    # Package container metadata exactly like ARM properties
                    raw_dict = {
                        "name": c_name,
                        "metadata": container.get("metadata", {}),
                        "publicAccess": container.get("public_access", "None")
                    }
                    
                    has_changed, current_hash = await self.check_state_differential(arn, raw_dict)
                    if not has_changed: continue
                        
                    raw_dict["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("Microsoft.Storage", "blobContainers", arn, raw_dict, baseline_risk))
            else:
                # PROD ARM EXTRACTION
                StorageManagementClient = getattr(importlib.import_module("azure.mgmt.storage"), "StorageManagementClient")
                client = StorageManagementClient(self.credential, self.subscription_id)
                
                accounts = await self.execute_with_backoff(
                    asyncio.to_thread, lambda: list(client.storage_accounts.list())
                )
                
                for sa in accounts:
                    sa_dict = sa.as_dict()
                    arn = sa_dict.get("id", "unknown-azure-id")
                    
                    has_changed, current_hash = await self.check_state_differential(arn, sa_dict)
                    if not has_changed: continue
                        
                    sa_dict["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("Microsoft.Storage", "storageAccounts", arn, sa_dict, baseline_risk))
                    
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] Storage extraction failed: {e}")
        return payloads

    async def _extract_virtual_machines(self, baseline_risk: float) -> List[Dict]:
        """Extracts VMs. Generates ARM-compliant Synthetic Overlays if running locally."""
        payloads = []
        try:
            if self.is_mocked:
                # SYNTHETIC OVERLAY: Simulate a VM backing the storage layer
                vm_dict = {
                    "id": f"/subscriptions/mock-sub/resourceGroups/local-rg/providers/Microsoft.Compute/virtualMachines/synth-vm-proxy",
                    "name": "synth-vm-proxy",
                    "location": "eastus",
                    "properties": {
                        "hardwareProfile": {"vmSize": "Standard_DS2_v2"},
                        "networkProfile": {"networkInterfaces": [{"id": "nic-01"}]}
                    },
                    "tags": {"Environment": "LocalMesh", "Role": "Proxy"}
                }
                arn = vm_dict["id"]
                has_changed, current_hash = await self.check_state_differential(arn, vm_dict)
                if has_changed:
                    vm_dict["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("Microsoft.Compute", "virtualMachines", arn, vm_dict, baseline_risk))
            else:
                ComputeManagementClient = getattr(importlib.import_module("azure.mgmt.compute"), "ComputeManagementClient")
                client = ComputeManagementClient(self.credential, self.subscription_id)
                vms = await self.execute_with_backoff(asyncio.to_thread, lambda: list(client.virtual_machines.list_all()))
                
                for vm in vms:
                    vm_dict = vm.as_dict()
                    arn = vm_dict.get("id", "unknown-azure-id")
                    has_changed, current_hash = await self.check_state_differential(arn, vm_dict)
                    if not has_changed: continue
                    vm_dict["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("Microsoft.Compute", "virtualMachines", arn, vm_dict, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] Virtual Machine extraction failed: {e}")
        return payloads

    async def _extract_network_security_groups(self, baseline_risk: float) -> List[Dict]:
        """Extracts NSGs. Generates ARM-compliant Synthetic Overlays if running locally."""
        payloads = []
        try:
            if self.is_mocked:
                # SYNTHETIC OVERLAY: Simulate a vulnerable NSG attached to the proxy VM
                nsg_dict = {
                    "id": f"/subscriptions/mock-sub/resourceGroups/local-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-vulnerable-01",
                    "name": "nsg-vulnerable-01",
                    "location": "eastus",
                    "properties": {
                        "securityRules": [
                            {"name": "AllowSSH", "properties": {"access": "Allow", "destinationPortRange": "22", "direction": "Inbound", "sourceAddressPrefix": "*"}}
                        ]
                    }
                }
                arn = nsg_dict["id"]
                has_changed, current_hash = await self.check_state_differential(arn, nsg_dict)
                if has_changed:
                    nsg_dict["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("Microsoft.Network", "networkSecurityGroups", arn, nsg_dict, baseline_risk))
            else:
                NetworkManagementClient = getattr(importlib.import_module("azure.mgmt.network"), "NetworkManagementClient")
                client = NetworkManagementClient(self.credential, self.subscription_id)
                nsgs = await self.execute_with_backoff(asyncio.to_thread, lambda: list(client.network_security_groups.list_all()))
                
                for nsg in nsgs:
                    nsg_dict = nsg.as_dict()
                    arn = nsg_dict.get("id", "unknown-azure-id")
                    has_changed, current_hash = await self.check_state_differential(arn, nsg_dict)
                    if not has_changed: continue
                    nsg_dict["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("Microsoft.Network", "networkSecurityGroups", arn, nsg_dict, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] NSG extraction failed: {e}")
        return payloads

    async def _extract_key_vaults(self, baseline_risk: float) -> List[Dict]:
        """Extracts Key Vaults. Generates ARM-compliant Synthetic Overlays if running locally."""
        payloads = []
        try:
            if self.is_mocked:
                # SYNTHETIC OVERLAY: Simulate an overly permissive Key Vault
                kv_dict = {
                    "id": f"/subscriptions/mock-sub/resourceGroups/local-rg/providers/Microsoft.KeyVault/vaults/kv-open-access-01",
                    "name": "kv-open-access-01",
                    "properties": {
                        "accessPolicies": [{"objectId": "00000000-0000-0000-0000-000000000000", "permissions": {"keys": ["get", "list"]}}]
                    }
                }
                arn = kv_dict["id"]
                has_changed, current_hash = await self.check_state_differential(arn, kv_dict)
                if has_changed:
                    kv_dict["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("Microsoft.KeyVault", "vaults", arn, kv_dict, baseline_risk))
            else:
                KeyVaultManagementClient = getattr(importlib.import_module("azure.mgmt.keyvault"), "KeyVaultManagementClient")
                client = KeyVaultManagementClient(self.credential, self.subscription_id)
                vaults = await self.execute_with_backoff(asyncio.to_thread, lambda: list(client.vaults.list_by_subscription()))
                
                for vault in vaults:
                    vault_dict = vault.as_dict()
                    arn = vault_dict.get("id", "unknown-azure-id")
                    has_changed, current_hash = await self.check_state_differential(arn, vault_dict)
                    if not has_changed: continue
                    vault_dict["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("Microsoft.KeyVault", "vaults", arn, vault_dict, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] Key Vault extraction failed: {e}")
        return payloads

    # ==========================================================================
    # MASTER EXECUTION PIPELINE
    # ==========================================================================

    async def run_full_discovery(self) -> List[Dict[str, Any]]:
        """
        The main ingestion pipeline. 
        Executes isolated service extractions based on registry definitions.
        If missing in local development, defaults to Deep Scan logic.
        """
        self.logger.info(f"[{self.tenant.id}] Initiating Full Azure Telemetry Extraction...")
        total_payloads = []
        
        azure_registry = config.service_registry.get("azure", {})
        
        tasks = []

        # --- DATA PLANE (Storage) ---
        risk = azure_registry.get("storage_account", {}).get("baseline_risk_score", 0.4)
        tasks.append(self._extract_storage_accounts(risk))
            
        # --- MANAGEMENT PLANE (Compute/Network/Security) ---
        risk = azure_registry.get("virtual_machine", {}).get("baseline_risk_score", 0.5)
        tasks.append(self._extract_virtual_machines(risk))
            
        risk = azure_registry.get("network_security_group", {}).get("baseline_risk_score", 0.2)
        tasks.append(self._extract_network_security_groups(risk))
            
        risk = azure_registry.get("key_vault", {}).get("baseline_risk_score", 0.9)
        tasks.append(self._extract_key_vaults(risk))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"[{self.tenant.id}] A service extraction task crashed: {result}")
            elif isinstance(result, list):
                total_payloads.extend(result)

        self.logger.info(f"[{self.tenant.id}] Discovery Complete. {len(total_payloads)} fresh nodes acquired.")
        return total_payloads