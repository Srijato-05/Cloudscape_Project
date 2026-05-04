import json
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

from core.config import TenantConfig, config

logger = logging.getLogger("CloudScape.CorrelationEngine")

# ==============================================================================
# PROJECT CLOUDSCAPE: ENTERPRISE TRUST & NETWORK CORRELATION ENGINE
# ==============================================================================

class EnterpriseCorrelationEngine:
    """
    Advanced Graph Correlation logic.
    This engine does not execute network calls. It ingests the raw forensic state
    dumped by the discovery engines and calculates the 'Edges' (relationships)
    that span across isolated project boundaries.
    """

    def __init__(self, tenant_registry: List[TenantConfig] = None):
        tenant_registry = tenant_registry or list(config.tenants.values())
        # Create a fast-lookup map connecting AWS Account IDs to our internal Project IDs
        self.account_to_tenant_map = {
            t.account_id: t.id for t in tenant_registry if t.provider == "aws" and t.account_id
        }
        logger.debug(f"Initialized Correlation Engine with mapped accounts: {list(self.account_to_tenant_map.keys())}")

    def _parse_arn(self, arn: str) -> Optional[Dict[str, str]]:
        """
        Deconstructs an Amazon Resource Name (ARN) into its constituent parts.
        Format: arn:partition:service:region:account-id:resource-id
        """
        match = re.match(r'^arn:(aws[a-zA-Z-]*):([^:]+):([^:]*):([0-9]{12}|aws|):(.+)$', arn)
        if not match:
            return None
        return {
            "partition": match.group(1),
            "service": match.group(2),
            "region": match.group(3),
            "account_id": match.group(4),
            "resource": match.group(5)
        }

    def analyze_iam_trusts(self, source_tenant: TenantConfig, raw_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes the AssumeRolePolicyDocument attached to IAM Roles.
        If a Role in Project A allows an entity from Project B to assume it,
        this method generates a specific cross-tenant Neo4j Edge.
        """
        cross_links = []
        roles = raw_state.get("IAM", {}).get("Roles", [])

        for role in roles:
            role_arn = role.get("Arn")
            trust_policy_str = role.get("AssumeRolePolicyDocument")
            
            if not trust_policy_str:
                continue
                
            try:
                # Boto3 sometimes returns policies as dicts, sometimes as url-encoded strings. 
                # We handle both to prevent pipeline crashes.
                if isinstance(trust_policy_str, str):
                    from urllib.parse import unquote
                    trust_policy = json.loads(unquote(trust_policy_str))
                else:
                    trust_policy = trust_policy_str

                statements = trust_policy.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") == "Allow" and "sts:AssumeRole" in str(stmt.get("Action", "")):
                        principals = stmt.get("Principal", {})
                        
                        # Principals can be AWS accounts, Services, or specific users
                        aws_principals = principals.get("AWS", [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]

                        for principal_arn in aws_principals:
                            # Is this a wildcard or a specific external account?
                            if principal_arn == "*":
                                cross_links.append({
                                    "source_node": "GLOBAL_INTERNET",
                                    "target_node": role_arn,
                                    "relationship": "CAN_ASSUME_ROLE",
                                    "metadata": {"risk": "CRITICAL", "reason": "Wildcard Trust Policy"}
                                })
                                continue

                            parsed_principal = self._parse_arn(principal_arn)
                            if parsed_principal and parsed_principal["account_id"] != source_tenant.account_id:
                                # We found a cross-account link!
                                target_project_id = self.account_to_tenant_map.get(parsed_principal["account_id"], "EXTERNAL_UNKNOWN")
                                
                                cross_links.append({
                                    "source_node": principal_arn,
                                    "target_node": role_arn,
                                    "relationship": "CAN_ASSUME_ROLE",
                                    "metadata": {
                                        "source_project": target_project_id,
                                        "target_project": source_tenant.id,
                                        "is_internal_mesh": target_project_id != "EXTERNAL_UNKNOWN"
                                    }
                                })

            except Exception as e:
                logger.error(f"[{source_tenant.id}] Failed to parse Trust Policy for {role.get('RoleName')}: {e}")

        return cross_links

    def analyze_network_bridges(self, source_tenant: TenantConfig, raw_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes VPC Peering connections to map network-level lateral movement paths.
        """
        cross_links = []
        peerings = raw_state.get("Network", {}).get("PeeringConnections", [])

        for peer in peerings:
            status = peer.get("Status", {}).get("Code")
            if status != "active":
                continue

            requester = peer.get("RequesterVpcInfo", {})
            accepter = peer.get("AccepterVpcInfo", {})

            req_vpc = requester.get("VpcId")
            req_account = requester.get("OwnerId")
            acc_vpc = accepter.get("VpcId")
            acc_account = accepter.get("OwnerId")

            # If the peering crosses account boundaries
            if req_account != acc_account:
                req_project = self.account_to_tenant_map.get(req_account, "EXTERNAL_UNKNOWN")
                acc_project = self.account_to_tenant_map.get(acc_account, "EXTERNAL_UNKNOWN")

                cross_links.append({
                    "source_node": f"vpc-{req_vpc}",
                    "target_node": f"vpc-{acc_vpc}",
                    "relationship": "NETWORK_PEERED_TO",
                    "metadata": {
                        "source_project": req_project,
                        "target_project": acc_project,
                        "peering_id": peer.get("VpcPeeringConnectionId")
                    }
                })

        return cross_links

    def analyze_s3_trusts(self, source_tenant: TenantConfig, raw_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        [SIMPLE] Analyzes S3 Bucket Policies for cross-account or public data exposure.
        """
        cross_links = []
        buckets = raw_state.get("Storage", {}).get("S3Buckets", [])

        for bucket in buckets:
            bucket_arn = bucket.get("Arn")
            policy_str = bucket.get("Policy")
            
            if not policy_str:
                continue
                
            try:
                if isinstance(policy_str, str):
                    from urllib.parse import unquote
                    policy = json.loads(unquote(policy_str))
                else:
                    policy = policy_str

                statements = policy.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") == "Allow":
                        principals = stmt.get("Principal", {})
                        
                        aws_principals = principals.get("AWS", []) if isinstance(principals, dict) else principals
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]

                        for principal in aws_principals:
                            if principal == "*":
                                cross_links.append({
                                    "source_node": "GLOBAL_INTERNET",
                                    "target_node": bucket_arn,
                                    "relationship": "CAN_READ_DATA" if "Get" in str(stmt.get("Action")) else "CAN_WRITE_DATA",
                                    "metadata": {"risk": "CRITICAL", "reason": "Public S3 Bucket Policy"}
                                })
                                continue

                            parsed_principal = self._parse_arn(principal)
                            if parsed_principal and parsed_principal["account_id"] != source_tenant.account_id:
                                target_project_id = self.account_to_tenant_map.get(parsed_principal["account_id"], "EXTERNAL_UNKNOWN")
                                cross_links.append({
                                    "source_node": principal,
                                    "target_node": bucket_arn,
                                    "relationship": "CROSS_ACCOUNT_DATA_ACCESS",
                                    "metadata": {
                                        "source_project": target_project_id,
                                        "target_project": source_tenant.id,
                                        "is_internal_mesh": target_project_id != "EXTERNAL_UNKNOWN"
                                    }
                                })

            except Exception as e:
                logger.error(f"[{source_tenant.id}] Failed to parse S3 Policy for {bucket.get('Name')}: {e}")

        return cross_links

    def analyze_tgw_bridges(self, source_tenant: TenantConfig, raw_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        [ADVANCED] Analyzes AWS Transit Gateway (TGW) attachments to find hub-and-spoke lateral movement paths.
        """
        cross_links = []
        tgw_attachments = raw_state.get("Network", {}).get("TransitGatewayAttachments", [])

        for att in tgw_attachments:
            if att.get("State") != "available":
                continue

            tgw_owner = att.get("TransitGatewayOwnerId")
            resource_owner = att.get("ResourceOwnerId")
            resource_id = att.get("ResourceId")
            tgw_arn = f"arn:aws:ec2:{source_tenant.region}:{tgw_owner}:transit-gateway/{att.get('TransitGatewayId')}"

            # We focus on cross-account attachments
            if tgw_owner != resource_owner:
                req_project = self.account_to_tenant_map.get(resource_owner, "EXTERNAL_UNKNOWN")
                tgw_project = self.account_to_tenant_map.get(tgw_owner, "EXTERNAL_UNKNOWN")

                cross_links.append({
                    "source_node": f"vpc-{resource_id}" if att.get("ResourceType") == "vpc" else resource_id,
                    "target_node": tgw_arn,
                    "relationship": "ATTACHED_TO_TGW",
                    "metadata": {
                        "source_project": req_project,
                        "target_project": tgw_project,
                        "is_internal_mesh": req_project != "EXTERNAL_UNKNOWN" and tgw_project != "EXTERNAL_UNKNOWN"
                    }
                })

        return cross_links

    def analyze_ram_shares(self, source_tenant: TenantConfig, raw_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        [EXTREME] Analyzes AWS Resource Access Manager (RAM) to detect implicitly shared subnets, 
        allowing container breakout across tenant boundaries.
        """
        cross_links = []
        ram_shares = raw_state.get("Network", {}).get("ResourceShares", [])

        for share in ram_shares:
            if share.get("status") != "ACTIVE":
                continue

            owner = share.get("owningAccountId")
            
            # This is a simplification of the payload, assuming 'principals' and 'resources' are lists of ARNs
            principals = share.get("principals", [])
            resources = share.get("resources", [])

            for principal in principals:
                parsed_principal = self._parse_arn(principal)
                target_account = parsed_principal["account_id"] if parsed_principal else principal
                
                if target_account != owner:
                    req_project = self.account_to_tenant_map.get(target_account, "EXTERNAL_UNKNOWN")
                    owner_project = self.account_to_tenant_map.get(owner, "EXTERNAL_UNKNOWN")

                    for resource in resources:
                        cross_links.append({
                            "source_node": principal,
                            "target_node": resource,
                            "relationship": "RAM_SHARED_SUBNET",
                            "metadata": {
                                "source_project": req_project,
                                "target_project": owner_project,
                                "risk": "CRITICAL",
                                "reason": "Subnet shared via RAM enables implicit container migration"
                            }
                        })

        return cross_links

    def extract_mesh_edges(self, source_tenant: TenantConfig, raw_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        The Master Execution function for this module.
        Executes all correlation analyzers and returns a unified list of Graph Edges.
        """
        logger.info(f"[{source_tenant.id}] Running Correlation Analysis against raw state...")
        
        all_edges = []
        all_edges.extend(self.analyze_iam_trusts(source_tenant, raw_state))
        all_edges.extend(self.analyze_network_bridges(source_tenant, raw_state))
        all_edges.extend(self.analyze_s3_trusts(source_tenant, raw_state))
        all_edges.extend(self.analyze_tgw_bridges(source_tenant, raw_state))
        all_edges.extend(self.analyze_ram_shares(source_tenant, raw_state))
        
        internal_links = len([e for e in all_edges if e.get("metadata", {}).get("is_internal_mesh")])
        external_links = len(all_edges) - internal_links
        
        logger.info(f"[{source_tenant.id}] Correlation Complete. Found {internal_links} Internal Mesh Edges, {external_links} External Edges.")
        
        return all_edges