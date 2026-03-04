import logging
import json
from typing import Any, Dict, List, Optional

from core.config import config

# ==============================================================================
# ENTERPRISE IDENTITY FABRIC ENGINE (NEXUS 5.0 AETHER)
# ==============================================================================

class IdentityFabricEngine:
    """
    Advanced cross-cloud identity resolution engine.
    Detects complex privilege escalation paths (Shadow Admins) and cross-cloud 
    federation trusts (Azure Entra ID -> AWS IAM).
    Outputs raw Graph Edges for ingestion.
    """

    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.IdentityFabric")
        
        # Shadow Admin escalation primitives
        # If an identity has ONE of these pairs, they can autonomously grant themselves full Admin.
        self.escalation_vectors = [
            {"iam:PassRole", "ec2:RunInstances"},     # Create an EC2 with Admin role, then SSH into it.
            {"iam:CreateAccessKey"},                  # Create a new access key for an existing Admin user.
            {"iam:CreatePolicyVersion"},              # Rewrite an attached policy to grant "*:*".
            {"iam:AttachUserPolicy"},                 # Attach AdministratorAccess to yourself.
            {"lambda:UpdateFunctionCode", "iam:PassRole"} # Hijack a Lambda function running as Admin.
        ]

    def _normalize_statement(self, statement: Any) -> List[Dict[str, Any]]:
        """Safely normalizes IAM statement blocks which can be dicts or lists of dicts."""
        if not statement:
            return []
        if isinstance(statement, dict):
            return [statement]
        if isinstance(statement, list):
            return statement
        return []

    def _evaluate_shadow_admin_risk(self, identity_arn: str, allowed_actions: set) -> List[Dict[str, Any]]:
        """
        Calculates if the set of allowed actions contains a known Privilege Escalation primitive.
        Returns a list of synthetic Neo4j Graph Edges representing the hidden escalation path.
        """
        edges = []
        try:
            for vector in self.escalation_vectors:
                # Check if the allowed actions represent a superset of the required escalation vector
                if vector.issubset(allowed_actions) or "*" in allowed_actions or "iam:*" in allowed_actions:
                    
                    vector_str = " | ".join(vector) if isinstance(vector, set) else "*"
                    
                    self.logger.warning(f"[SHADOW ADMIN DETECTED] {identity_arn} can escalate via: {vector_str}")
                    
                    # Create a "Ghost Edge" representing the ability to become an Admin
                    edge = {
                        "source_arn": identity_arn,
                        "target_arn": "arn:aws:iam::system:pseudo:admin_tier",
                        "relationship_type": "CAN_ESCALATE_TO_ADMIN",
                        "target_label": "PrivilegeTier",
                        "properties": {
                            "escalation_vector": vector_str,
                            "severity": "CRITICAL"
                        }
                    }
                    edges.append(edge)
                    # If they are already an admin via one vector, we don't need to log 5 different vectors
                    break 

        except Exception as e:
            self.logger.error(f"Failed to evaluate Shadow Admin risk for {identity_arn}: {e}")

        return edges

    def map_cross_cloud_trusts(self, aws_roles: List[Dict[str, Any]], azure_identities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        The Cross-Cloud Lateral Movement Calculator.
        Scans AWS 'AssumeRolePolicyDocument' (Trust Policies) for OIDC or SAML federations 
        that match discovered Azure Entra ID / App Registration Client IDs.
        """
        self.logger.info("Calculating Cross-Cloud Identity Federation Trusts...")
        cross_cloud_edges = []

        try:
            # 1. Build a quick lookup dictionary of Azure Identities
            # Maps Azure Application ID (Client ID) to its specific Graph Node ID
            azure_lookup = {}
            for az_identity in azure_identities:
                props = az_identity.get("properties", {})
                client_id = props.get("appId", props.get("clientId"))
                az_arn = az_identity.get("metadata", {}).get("arn")
                
                if client_id and az_arn:
                    azure_lookup[str(client_id).lower()] = az_arn

            if not azure_lookup:
                self.logger.debug("No Azure Client IDs found for cross-cloud correlation. Skipping.")
                return []

            # 2. Iterate through AWS Roles and parse their Trust Policies
            for role in aws_roles:
                role_arn = role.get("metadata", {}).get("arn")
                assume_role_policy_str = role.get("properties", {}).get("AssumeRolePolicyDocument")

                if not role_arn or not assume_role_policy_str:
                    continue

                try:
                    # Convert URL-encoded/stringified JSON into a Python Dictionary
                    assume_role_policy = assume_role_policy_str
                    if isinstance(assume_role_policy, str):
                        assume_role_policy = json.loads(assume_role_policy)

                    statements = self._normalize_statement(assume_role_policy.get("Statement"))
                    
                    for statement in statements:
                        if statement.get("Effect") != "Allow":
                            continue
                            
                        # Extract the Principal (Who is allowed to assume this role?)
                        principal = statement.get("Principal", {})
                        
                        # Federation via OIDC/SAML
                        federated = principal.get("Federated", "")
                        
                        # Sometimes the specific Client ID is locked in a StringEquals condition
                        conditions = statement.get("Condition", {}).get("StringEquals", {})
                        aud_claims = conditions.get("sts:ExternalId", conditions.get("graph.microsoft.com:aud", ""))
                        
                        # Normalize claims to a list for iteration
                        if isinstance(aud_claims, str):
                            aud_claims = [aud_claims]

                        # 3. The Mathematical Bridge: Does the AWS Condition match a known Azure App ID?
                        for claim in aud_claims:
                            claim_lower = str(claim).lower()
                            if claim_lower in azure_lookup:
                                azure_source_arn = azure_lookup[claim_lower]
                                
                                self.logger.critical(f"[CROSS-CLOUD BRIDGE] Azure App '{claim}' can assume AWS Role '{role_arn}'")
                                
                                # Generate the Cross-Cloud Relationship Edge
                                edge = {
                                    "source_arn": azure_source_arn,
                                    "target_arn": role_arn,
                                    "relationship_type": "ASSUMES_ROLE_CROSS_CLOUD",
                                    "target_label": "AWSRole",
                                    "properties": {
                                        "federation_type": str(federated),
                                        "matched_claim": str(claim),
                                        "severity": "CRITICAL"
                                    }
                                }
                                cross_cloud_edges.append(edge)

                except json.JSONDecodeError:
                    self.logger.debug(f"Could not parse AssumeRolePolicyDocument for {role_arn}")
                    continue
                except Exception as e:
                    self.logger.error(f"Error processing Trust Policy for {role_arn}: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Catastrophic failure in cross-cloud mapping: {e}")

        return cross_cloud_edges

    def extract_identity_edges(self, all_payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        The Main Public Orchestrator.
        Takes the complete Universal Resource Model (URM) payload list, filters out 
        the identity nodes, runs the advanced heuristic analysis, and returns the new graph edges.
        """
        self.logger.info("Commencing Global Identity Fabric Analysis...")
        
        all_new_edges = []
        
        aws_roles = []
        azure_identities = []

        try:
            # 1. Filter the payloads into specific Identity buckets
            for payload in all_payloads:
                meta = payload.get("metadata", {})
                provider = meta.get("provider", "").lower()
                resource_type = meta.get("resource_type", "")
                
                if provider == "aws" and resource_type == "Role":
                    aws_roles.append(payload)
                elif provider == "azure" and resource_type in ["ServicePrincipal", "Application"]:
                    azure_identities.append(payload)

            # 2. Run Cross-Cloud Federation Mapping
            if aws_roles and azure_identities:
                cross_edges = self.map_cross_cloud_trusts(aws_roles, azure_identities)
                all_new_edges.extend(cross_edges)

            # 3. Run Shadow Admin Detection (AWS)
            for role in aws_roles:
                role_arn = role.get("metadata", {}).get("arn")
                # In Nexus 5.0, the Effective Permission Resolver (EPR) adds a flat list of allowed actions
                allowed_actions = set(role.get("properties", {}).get("_flattened_allowed_actions", []))
                
                if allowed_actions:
                    escalation_edges = self._evaluate_shadow_admin_risk(role_arn, allowed_actions)
                    all_new_edges.extend(escalation_edges)

            self.logger.info(f"Identity Fabric Analysis complete. Generated {len(all_new_edges)} heuristic edges.")

        except Exception as e:
            self.logger.error(f"Identity Fabric Analysis failed: {e}", exc_info=True)

        return all_new_edges

# ==============================================================================
# GLOBAL EXPORT
# ==============================================================================
identity_fabric = IdentityFabricEngine()