import os
import json
import logging
from azure.identity import DefaultAzureCredential, AzureCliCredential # type: ignore
from azure.mgmt.resource import ResourceManagementClient # type: ignore
from azure.mgmt.compute import ComputeManagementClient # type: ignore

logger = logging.getLogger(__name__)

class AzureScraper:
    def __init__(self):
        # Resolve to standardized repository-relative mount paths
        self.persistence_path = os.getenv("CLOUDSCAPE_AZURE_MANIFEST_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../volume/azure_data")))
        os.makedirs(self.persistence_path, exist_ok=True)
        
        # Identity Logic: Use CLI first for Student Accounts
        try:
            self.credential = AzureCliCredential()
            # Subscription ID from your 'az login' output
            self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "dd674fe3-337c-4cae-871b-9d6774f91a25")
            
            # Clients for Resource Groups and VMs
            self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
        except Exception as e:
            logger.critical(f"Critical Azure Auth Failure: {str(e)}", exc_info=True)
            raise

    def fetch_all_resources(self):
        inventory = {
            "resource_groups": [],
            "virtual_machines": []
        }

        try:
            logger.info("Scanning Azure Resource Groups...")
            for rg in self.resource_client.resource_groups.list():
                inventory["resource_groups"].append({
                    "name": rg.name,
                    "id": rg.id,
                    "location": rg.location,
                    "tags": rg.tags or {}
                })

            logger.info("Scanning Azure Virtual Machines...")
            for vm in self.compute_client.virtual_machines.list_all():
                inventory["virtual_machines"].append({
                    "name": vm.name,
                    "id": vm.id,
                    "location": vm.location,
                    "size": vm.hardware_profile.vm_size,
                    "os": vm.storage_profile.os_disk.os_type.value
                })

            # Save full advanced manifest to E: Drive
            output_file = f"{self.persistence_path}/azure_inventory.json"
            with open(output_file, "w") as f:
                json.dump(inventory, f, indent=4)
            
            logger.info(f"Azure Scan Complete. Saved {len(inventory['resource_groups'])} RGs and {len(inventory['virtual_machines'])} VMs.")
            
        except Exception as e:
            logger.error(f"Azure Ingestion Error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    # Unit test for the driver
    scraper = AzureScraper()
    scraper.fetch_all_resources()