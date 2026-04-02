import logging
from typing import Dict, Any, List
import uuid

class AzureServiceMock:
    """
    Custom stateful Azure API Simulator.
    Simulates ARM and Blob Storage management planes.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Mock.Azure")
        self.resources = {}

    def mock_list_resources(self, subscription_id: str) -> List[Dict[str, Any]]:
        """Simulates list_resources across multiple types."""
        return [
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/CS-PROD/providers/Microsoft.Compute/virtualMachines/AzVM-01",
                "name": "AzVM-01",
                "type": "Microsoft.Compute/virtualMachines",
                "location": "eastus",
                "tags": {"Environment": "Production"}
            },
            {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/CS-PROD/providers/Microsoft.Storage/storageAccounts/csblob01",
                "name": "csblob01",
                "type": "Microsoft.Storage/storageAccounts",
                "location": "eastus"
            }
        ]

    def mock_get_blobs(self, account_name: str) -> List[str]:
        """Simulates blob listing."""
        return ["forensic_report_01.pdf", "secret_vault.db"]

azure_mock = AzureServiceMock()
