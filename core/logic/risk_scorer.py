import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from core.config import config, TenantConfig

# ==============================================================================
# ENTERPRISE RISK SCORING ENGINE (NEXUS 5.0 AETHER)
# ==============================================================================
# Calculates the 'Blast Radius' and 'Mathematical Cost' of cloud resources.
# This engine evaluates baseline registry risk, network exposure, IAM 
# over-privilege, and strict compliance framework multipliers.
# ==============================================================================

class RiskScoringEngine:
    """
    Advanced Heuristic Risk Calculator.
    Generates deterministic float values [0.0 - 1.0] used as edge weights 
    by the Dijkstra Attack Path Engine.
    """

    def __init__(self):
        self.logger = logging.getLogger("Cloudscape.Logic.RiskScorer")
        
        # [AETHER UPGRADE] Accessing validated Pydantic attributes via Dot Notation
        # This prevents the AttributeError crash caused by old dictionary .get() calls
        try:
            risk_cfg = config.settings.logic_engine.risk_scoring
            self.enabled = risk_cfg.enabled
            self.exposure_penalty = risk_cfg.public_exposure_penalty / 100.0
            self.admin_penalty = risk_cfg.admin_privilege_penalty / 100.0
        except AttributeError as e:
            self.logger.critical(f"FATAL: Risk Engine failed to bind to Pydantic configuration: {e}")
            self.enabled = False

        # Internal Multipliers for specific cloud threat vectors
        self.COMPLIANCE_PENALTY = 0.15
        self.DATA_GRAVITY_PENALTY = 0.20
        self.LATERAL_MOVEMENT_PENALTY = 0.10

    def _calculate_base_score(self, provider: str, resource_type: str) -> float:
        """Retrieves the mathematical baseline from the Universal Service Registry."""
        registry = config.service_registry.get(provider.lower(), {})
        
        # Search the registry for the matching resource type
        for key, service_def in registry.items():
            if service_def.get("resource_type") == resource_type:
                return float(service_def.get("baseline_risk_score", 0.1))
                
        self.logger.debug(f"Resource type '{resource_type}' not found in registry. Defaulting to 0.1")
        return 0.1

    def _evaluate_environment_context(self, env_type: str) -> float:
        """Applies multipliers based on the Pydantic-validated environment tier."""
        env_type = env_type.lower()
        if env_type == "production":
            return 1.50
        elif env_type == "dr":
            return 1.30
        elif env_type == "finance":
            return 1.60
        elif env_type == "shared-services":
            return 1.20
        elif env_type == "development":
            return 0.80
        elif env_type == "sandbox":
            return 0.50
        return 1.0

    def _evaluate_compliance_impact(self, tags: Dict[str, str]) -> float:
        """Checks for regulatory frameworks (PCI-DSS, SOC2, HIPAA) attached to the tenant/resource."""
        penalty = 0.0
        compliance_tag = tags.get("compliance", "").lower()
        
        if any(fw in compliance_tag for fw in ["pci-dss", "hipaa", "soc2", "fedramp", "iso-27001"]):
            penalty += self.COMPLIANCE_PENALTY
            
        return penalty

    def _evaluate_network_exposure(self, properties: Dict[str, Any], resource_type: str) -> float:
        """Deep dictionary parsing to detect Public IPs, 0.0.0.0/0 Security Groups, and open S3 ACLs."""
        penalty = 0.0
        prop_str = str(properties).lower()

        # 1. Direct Public IP Assignments
        if "publicipaddress" in prop_str or properties.get("PublicIpAddress"):
            penalty += (self.exposure_penalty * 0.8)

        # 2. Open Security Groups (AWS/Azure)
        if resource_type in ["SecurityGroup", "NetworkSecurityGroup"]:
            if "0.0.0.0/0" in prop_str or "internet" in prop_str:
                penalty += self.exposure_penalty

        # 3. Storage Account / S3 Bucket Public Access
        if resource_type in ["Bucket", "StorageAccount"]:
            if properties.get("PublicAccess") == "Enabled" or "publicread" in prop_str:
                penalty += self.exposure_penalty
                
            # Aether specific check for secondary metadata PAB configurations
            sec_meta = properties.get("_secondary_metadata", {})
            pab = sec_meta.get("get_public_access_block", {})
            if pab and pab.get("BlockPublicAcls") is False:
                penalty += (self.exposure_penalty * 0.5)

        return penalty

    def _evaluate_iam_heuristics(self, properties: Dict[str, Any], resource_type: str) -> float:
        """Scans attached JSON policies for wildcards, pass-role, and shadow-admin signatures."""
        penalty = 0.0
        
        if resource_type not in ["Role", "User", "Group", "Policy", "RoleAssignment"]:
            return penalty

        sec_meta = properties.get("_secondary_metadata", {})
        attached_policies = sec_meta.get("AttachedPolicies", [])
        
        # Check for literal AdministratorAccess
        for policy in attached_policies:
            if "AdministratorAccess" in str(policy.get("PolicyArn", "")):
                return self.admin_penalty

        # Check Azure Role Assignments for Owner/Contributor
        role_assignments = sec_meta.get("RoleAssignments", [])
        for assignment in role_assignments:
            role_id = str(assignment.get("roleDefinitionId", "")).lower()
            if "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" in role_id: # Azure Owner GUID
                return self.admin_penalty

        # Deep JSON string analysis for complex wildcards
        prop_str = str(properties).replace(" ", "")
        if "\"Action\":\"*\"" in prop_str and "\"Resource\":\"*\"" in prop_str:
            penalty += self.admin_penalty
        elif "iam:PassRole" in prop_str or "iam:CreateUser" in prop_str:
            penalty += self.LATERAL_MOVEMENT_PENALTY

        return penalty

    def _calculate_data_gravity(self, tags: Dict[str, str]) -> float:
        """Evaluates the data sensitivity tag to increase target value."""
        sensitivity = tags.get("data_sensitivity", "low").lower()
        if sensitivity == "critical":
            return self.DATA_GRAVITY_PENALTY
        elif sensitivity == "high":
            return self.DATA_GRAVITY_PENALTY * 0.75
        elif sensitivity == "medium":
            return self.DATA_GRAVITY_PENALTY * 0.30
        return 0.0

    def calculate_node_risk(self, urm_payload: Dict[str, Any], tenant: TenantConfig) -> float:
        """
        The Core Execution Engine.
        Ingests the Universal Resource Model payload, runs it through all heuristic
        analyzers, and outputs a normalized Blast Radius score.
        """
        if not self.enabled:
            return 0.0

        try:
            metadata = urm_payload.get("metadata", {})
            properties = urm_payload.get("properties", {})
            merged_tags = {**tenant.tags, **urm_payload.get("tags", {})}
            
            provider = metadata.get("provider", "unknown")
            resource_type = metadata.get("resource_type", "unknown")
            arn = metadata.get("arn", "unknown")

            # 1. Base Score & Environment Multiplier
            base_score = self._calculate_base_score(provider, resource_type)
            env_multiplier = self._evaluate_environment_context(tenant.environment_type)
            
            raw_score = base_score * env_multiplier

            # 2. Add Heuristic Penalties
            compliance_penalty = self._evaluate_compliance_impact(merged_tags)
            network_penalty = self._evaluate_network_exposure(properties, resource_type)
            iam_penalty = self._evaluate_iam_heuristics(properties, resource_type)
            gravity_penalty = self._calculate_data_gravity(merged_tags)

            # 3. Aggregate Total Mathematical Risk
            total_score = raw_score + compliance_penalty + network_penalty + iam_penalty + gravity_penalty

            # 4. Clamp the final float strictly between 0.0 and 1.0 for Dijkstra
            final_clamped_score = min(max(total_score, 0.0), 1.0)
            
            # Detailed debug logging for transparent math tracking
            if final_clamped_score > 0.8:
                self.logger.debug(
                    f"CRITICAL RISK IDENTIFIED | ARN: {arn} | "
                    f"Score: {final_clamped_score:.2f} (Base: {base_score}, Env: {env_multiplier}x, "
                    f"NetPen: +{network_penalty:.2f}, IAMPen: +{iam_penalty:.2f})"
                )

            return round(final_clamped_score, 3)

        except Exception as e:
            self.logger.error(f"Failed to calculate risk for node: {e}", exc_info=True)
            return 0.0

# ==============================================================================
# GLOBAL EXPORT
# ==============================================================================
# Instantiated locally to maintain configuration state in memory
risk_scorer = RiskScoringEngine()