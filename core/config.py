import os
import sys
import json
import yaml
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ValidationError

# ==============================================================================
# ENTERPRISE CONFIGURATION VALIDATOR & STATE MANAGER (NEXUS 5.0 AETHER)
# ==============================================================================
# Resolves absolute paths mathematically to ensure Docker/Host execution consistency
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s")
logger = logging.getLogger("Cloudscape.Config")

# ------------------------------------------------------------------------------
# 1. PYDANTIC SCHEMAS FOR SETTINGS.YAML
# ------------------------------------------------------------------------------

class AppMetadata(BaseModel):
    name: str = Field(..., description="Application Name")
    version: str = Field(..., description="Semantic Versioning")
    description: str

class DatabaseIngestion(BaseModel):
    batch_size: int = Field(default=2500, ge=100, le=20000, description="UNWIND chunk size")

class DatabaseConfig(BaseModel):
    uri: str = Field(..., description="Neo4j Bolt URI")
    connection_pool_size: int = Field(default=100, ge=1)
    connection_timeout_sec: int = Field(default=15)
    transaction_retry_time_sec: int = Field(default=30)
    ingestion: DatabaseIngestion

# [AETHER UPGRADE] Fully saturated Orchestrator block for legacy engine compatibility
class OrchestratorConfig(BaseModel):
    max_concurrent_tenants: int = Field(default=10, ge=1)
    hybrid_merge_strategy: str = Field(default="deep_merge")
    enable_state_differential: bool = Field(default=False, description="Use state cache to avoid re-ingesting unchanged nodes")
    worker_timeout_sec: int = Field(default=300, ge=30, description="Max execution time per tenant worker")

class ForensicsConfig(BaseModel):
    output_directory: str
    generate_json_evidence: bool = True
    compress_reports: bool = True
    slack_alerts_enabled: bool = False

class RiskScoringConfig(BaseModel):
    enabled: bool = True
    public_exposure_penalty: float = Field(default=25.0, ge=0.0)
    admin_privilege_penalty: float = Field(default=50.0, ge=0.0)

class EPRConfig(BaseModel):
    enabled: bool = True
    flag_wildcard_actions: bool = True

class IdentityFabricConfig(BaseModel):
    enabled: bool = True
    flag_shadow_admins: bool = True
    cross_cloud_mapping: bool = True

class AttackPathDetectionConfig(BaseModel):
    enabled: bool = True
    max_path_cost: float = Field(default=20.0, gt=0.0)
    target_tags: List[str] = Field(default=["critical", "high"])

class LogicEngineConfig(BaseModel):
    risk_scoring: RiskScoringConfig
    effective_permission_resolver: EPRConfig
    identity_fabric: IdentityFabricConfig
    attack_path_detection: AttackPathDetectionConfig

class SimulationConfig(BaseModel):
    enabled: bool = True
    vulnerability_injection_rate: float = Field(default=0.05, ge=0.0, le=1.0)
    base_node_multiplier: int = Field(default=50, ge=1)

class CrawlingConfig(BaseModel):
    api_retry_max_attempts: int = Field(default=3, ge=1, description="Max network retries for 429/500 responses")
    api_retry_backoff_factor: float = Field(default=2.0, ge=1.0, description="Exponential backoff multiplier")
    timeout_seconds: int = Field(default=30, ge=5, description="Global API socket timeout limit")
    max_pagination_depth: int = Field(default=100, ge=1, description="Circuit breaker for infinite API pagination")
    concurrency_limit: int = Field(default=20, ge=1, description="Max simultaneous async workers per tenant")
    fail_open_on_access_denied: bool = Field(default=False, description="If True, skips 403s instead of crashing")
    rate_limit_calls_per_sec: float = Field(default=10.0, gt=0.0, description="Hard throttle for API dispatchers")
    verify_ssl: bool = Field(default=True, description="Strict TLS verification")
    max_worker_threads: int = Field(default=10, ge=1, description="Dedicated thread pool for blocking Boto3/Azure calls")
    user_agent: str = Field(default="Cloudscape-Nexus/5.0", description="Telemetry header identification")

class Settings(BaseModel):
    app_metadata: AppMetadata
    database: DatabaseConfig
    orchestrator: OrchestratorConfig
    forensics: ForensicsConfig
    logic_engine: LogicEngineConfig
    simulation: SimulationConfig
    crawling: CrawlingConfig

# ------------------------------------------------------------------------------
# 2. PYDANTIC SCHEMAS FOR TENANTS.YAML
# ------------------------------------------------------------------------------

class TenantCredentials(BaseModel):
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_default_region: Optional[str] = "us-east-1"
    aws_account_id: Optional[str] = None 
    
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_subscription_id: Optional[str] = None

class TenantConfig(BaseModel):
    id: str = Field(..., description="Unique Tenant Identifier")
    name: str = Field(..., description="Human readable name")
    provider: str = Field(..., pattern="^(?i)(aws|azure)$")
    environment_type: str = Field(default="production", pattern="^(?i)(production|development|sandbox|dr|finance|shared-services)$")
    credentials: TenantCredentials
    tags: Dict[str, str] = Field(default_factory=dict)

# ------------------------------------------------------------------------------
# 3. GLOBAL CONFIGURATION MANAGER
# ------------------------------------------------------------------------------

class ConfigurationManager:
    """
    Singleton class that reads, mathematically validates, and locks the global 
    application state into memory.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigurationManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Executes the strict loading and validation sequence."""
        self.settings: Settings = self._load_settings()
        self.tenants: List[TenantConfig] = self._load_tenants()
        self.service_registry: Dict[str, Any] = self._load_registry()
        
        logger.info(f"Configuration Manager Initialized. Aether Features Loaded successfully.")

    def _read_yaml(self, filepath: Path) -> Dict[str, Any]:
        """Safely parses YAML files."""
        if not filepath.exists():
            logger.critical(f"FATAL: Required configuration file missing: {filepath}")
            sys.exit(1)
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                return yaml.safe_load(file) or {}
        except yaml.YAMLError as e:
            logger.critical(f"FATAL: Malformed YAML in {filepath.name}: {e}")
            sys.exit(1)

    def _load_settings(self) -> Settings:
        """Loads and strictly validates settings.yaml"""
        settings_path = CONFIG_DIR / "settings.yaml"
        raw_settings = self._read_yaml(settings_path)
        try:
            return Settings(**raw_settings)
        except ValidationError as e:
            logger.critical(f"FATAL: Schema validation failed for settings.yaml:\n{e.json(indent=2)}")
            sys.exit(1)

    def _load_tenants(self) -> List[TenantConfig]:
        """Loads and strictly validates tenants.yaml"""
        tenants_path = CONFIG_DIR / "tenants.yaml"
        raw_data = self._read_yaml(tenants_path)
        raw_tenants = raw_data.get("tenants", [])
        
        valid_tenants = []
        try:
            for t_dict in raw_tenants:
                valid_tenants.append(TenantConfig(**t_dict))
            return valid_tenants
        except ValidationError as e:
            logger.critical(f"FATAL: Schema validation failed for tenants.yaml:\n{e.json(indent=2)}")
            sys.exit(1)

    def _load_registry(self) -> Dict[str, Any]:
        """Loads the Universal Service Registry JSON."""
        registry_path = CONFIG_DIR / "service_registry.json"
        if not registry_path.exists():
            logger.critical(f"FATAL: Required registry file missing: {registry_path}")
            sys.exit(1)
        try:
            with open(registry_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.critical(f"FATAL: Malformed JSON in service_registry.json: {e}")
            sys.exit(1)

# ==============================================================================
# GLOBAL EXPORT
# ==============================================================================
config = ConfigurationManager()