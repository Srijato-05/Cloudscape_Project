import logging
from typing import Dict, Any, List, Optional

class ScenarioLibrary:
    """
    Formalized repository of 'What-if' security mutations.
    Encapsulates industry-standard risk drift scenarios.
    """
    
    SCENARIO_REGISTRY = {
        "S3_BUCKET_EXPOSURE": {
            "description": "Mutate private S3 bucket to public listing and read access.",
            "mutations": [
                {"path": "metadata.IsPublic", "value": True},
                {"path": "properties.PublicAccessBlockConfiguration.BlockPublicAcls", "value": False},
                {"path": "properties.PublicAccessBlockConfiguration.IgnorePublicAcls", "value": False},
                {"path": "risk_score", "value": 9.5}
            ]
        },
        "IAM_PRIVILEGE_HOIST": {
            "description": "Elevate a service role to AdministratorAccess equivalent.",
            "mutations": [
                {"path": "properties.AttachedPolicies", "append": {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
                {"path": "risk_score", "value": 10.0},
                {"path": "metadata.IsAdmin", "value": True}
            ]
        },
        "NETWORK_EXPOSURE_SSH": {
            "description": "Open SSH (22) to the world on a Security Group.",
            "mutations": [
                {"path": "properties.IpPermissions", "append": {
                    "IpProtocol": "tcp", 
                    "FromPort": 22, 
                    "ToPort": 22, 
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }},
                {"path": "risk_score", "value": 8.5}
            ]
        },
        "DATABASE_PUBLIC_DRIFT": {
            "description": "Modify an RDS instance to be publicly accessible.",
            "mutations": [
                {"path": "properties.PubliclyAccessible", "value": True},
                {"path": "metadata.IsPublic", "value": True},
                {"path": "risk_score", "value": 9.0}
            ]
        },
        "AZURE_BLOB_ANONYMOUS": {
            "description": "Enable anonymous access on an Azure Storage Container.",
            "mutations": [
                {"path": "properties.publicAccess", "value": "Container"},
                {"path": "metadata.IsPublic", "value": True},
                {"path": "risk_score", "value": 9.2}
            ]
        },
        "EXFIL_CHAIN_APT29": {
            "description": "Sophisticated multi-vector drift: IAM Privilege Escalation + S3 Exposure + DNS Exfiltration Tunnel.",
            "mutations": [
                {"path": "properties.AttachedPolicies", "append": {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
                {"path": "metadata.IsPublic", "value": True},
                {"path": "properties.PublicAccessBlockConfiguration.BlockPublicAcls", "value": False},
                {"path": "properties.Network.DNS_Tunneled", "value": True},
                {"path": "risk_score", "value": 10.0}
            ]
        }
    }

    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Simulation.ScenarioLibrary")

    def get_scenario(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieves a scenario definition by name."""
        return self.SCENARIO_REGISTRY.get(name)

    def list_scenarios(self) -> List[str]:
        """Returns a list of all registered scenario names."""
        return list(self.SCENARIO_REGISTRY.keys())

scenario_library = ScenarioLibrary()
