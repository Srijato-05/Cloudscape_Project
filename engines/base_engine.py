import abc
import time
import json
import hashlib
import asyncio
import logging
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple
from datetime import datetime, timezone

# Optional Redis import for the State Differential Engine
try:
    import redis.asyncio as aioredis
    from redis.exceptions import RedisError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from core.config import config, TenantConfig

# ==============================================================================
# ENTERPRISE ASYNC RATE LIMITER (TOKEN BUCKET ALGORITHM)
# Prevents aggressive multi-threading from triggering Cloud Provider API blocks.
# ==============================================================================
class AsyncTokenBucket:
    """
    Highly precise asynchronous rate limiter.
    Ensures that across hundreds of threads, we never exceed the 
    rate_limit_calls_per_sec defined in settings.yaml.
    """
    def __init__(self, rate_limit_hz: float):
        self.capacity = float(rate_limit_hz)
        self.tokens = float(rate_limit_hz)
        self.rate = float(rate_limit_hz)
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        while True:
            async with self.lock:
                now = time.monotonic()
                time_passed = now - self.last_update
                self.tokens = min(self.capacity, self.tokens + time_passed * self.rate)
                self.last_update = now

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                
                # Calculate exact time needed to wait for the required tokens
                wait_time = (tokens - self.tokens) / self.rate
            
            # Yield control back to the event loop while waiting
            await asyncio.sleep(wait_time)


# ==============================================================================
# MOCK CREDENTIAL INJECTOR (NEXUS 5.0 AETHER)
# ==============================================================================
class MockAzureCredential:
    """
    Bypasses Microsoft Entra ID (login.microsoftonline.com) entirely.
    Injects a mathematically valid, unexpiring dummy token for Azurite testing.
    """
    def get_token(self, *scopes: str, **kwargs: Any) -> Any:
        from azure.core.credentials import AccessToken
        return AccessToken("mock-aether-token-1122334455", int(time.time()) + 3600)


# ==============================================================================
# ABSTRACT BASE ENGINE
# ==============================================================================
class BaseDiscoveryEngine(abc.ABC):
    """
    The Universal Interface for all Cloud/SaaS Discovery Engines.
    Implements fault-tolerant API execution, state hashing, and schema normalization.
    """

    def __init__(self, tenant: TenantConfig):
        self.tenant = tenant
        self.provider = tenant.provider.upper()
        self.logger = logging.getLogger(f"Cloudscape.Engine.{self.provider}.[{tenant.id}]")
        
        # ----------------------------------------------------------------------
        # 1. PYDANTIC CONFIGURATION BINDING
        # ----------------------------------------------------------------------
        try:
            crawl_cfg = config.settings.crawling
            self.max_retries = crawl_cfg.api_retry_max_attempts
            self.backoff_factor = crawl_cfg.api_retry_backoff_factor
            self.fail_open = crawl_cfg.fail_open_on_access_denied
            limit_hz = crawl_cfg.rate_limit_calls_per_sec
            self.verify_ssl = crawl_cfg.verify_ssl
            
            self.use_state_cache = config.settings.orchestrator.enable_state_differential
        except AttributeError as e:
            self.logger.critical(f"FATAL: Engine failed to bind to Pydantic configuration: {e}")
            raise
        
        # ----------------------------------------------------------------------
        # 2. CONCURRENCY & RATE LIMITING
        # ----------------------------------------------------------------------
        self.rate_limiter = AsyncTokenBucket(limit_hz)
        
        # ----------------------------------------------------------------------
        # 3. LOCAL MESH INTERCEPTION (LOCALSTACK / AZURITE)
        # ----------------------------------------------------------------------
        self.is_mocked = "endpoint_url" in self.tenant.tags
        self.mock_endpoint = self.tenant.tags.get("endpoint_url")
        
        if self.is_mocked:
            self.verify_ssl = False  # Disable SSL for localhost Docker traffic
            self.logger.debug(f"[{self.tenant.id}] Local Mesh Interception Active -> {self.mock_endpoint}")

        # ----------------------------------------------------------------------
        # 4. REDIS STATE DIFFERENTIAL ENGINE
        # ----------------------------------------------------------------------
        self.redis_client = None
        if self.use_state_cache:
            self._bootstrap_redis()

        self.logger.debug(f"[{self.tenant.id}] Engine Initialized. Rate Limit: {limit_hz}/sec. Cache Enabled: {self.use_state_cache}")

    def _bootstrap_redis(self) -> None:
        """Initializes the async Redis connection for the State Cache."""
        if not REDIS_AVAILABLE:
            self.logger.warning("Redis package not installed. State Differential Engine disabled.")
            self.use_state_cache = False
            return
            
        try:
            # Safely attempt to fetch Redis URI, fallback to standard localhost if not explicitly in config
            redis_uri = getattr(config.settings, "state_cache", None)
            redis_uri = redis_uri.uri if redis_uri else "redis://localhost:6379"

            self.redis_client = aioredis.from_url(
                redis_uri, 
                encoding="utf-8", 
                decode_responses=True
            )
        except Exception as e:
            self.logger.error(f"Failed to connect to State Cache (Redis): {e}. Falling back to full ingest.")
            self.use_state_cache = False

    # ==========================================================================
    # CONNECTION FACTORIES (THE AUTH FIX)
    # ==========================================================================

    def get_aws_client_kwargs(self, region_override: Optional[str] = None) -> Dict[str, Any]:
        """Dynamically constructs Boto3 arguments, hijacking credentials if mocked."""
        creds = self.tenant.credentials
        region = region_override or creds.aws_default_region

        kwargs = {
            "region_name": region,
            "verify": self.verify_ssl
        }

        if self.is_mocked:
            kwargs["endpoint_url"] = self.mock_endpoint
            kwargs["aws_access_key_id"] = "test"
            kwargs["aws_secret_access_key"] = "test"
        else:
            kwargs["aws_access_key_id"] = creds.aws_access_key_id
            kwargs["aws_secret_access_key"] = creds.aws_secret_access_key

        return kwargs

    def get_azure_credential(self) -> Any:
        """Yields Azure Auth. Uses MockAzureCredential to prevent Entra ID crashes."""
        if self.is_mocked:
            return MockAzureCredential()
            
        from azure.identity import ClientSecretCredential
        creds = self.tenant.credentials
        return ClientSecretCredential(
            tenant_id=creds.azure_tenant_id,
            client_id=creds.azure_client_id,
            client_secret=creds.azure_client_secret
        )

    # ==========================================================================
    # EXECUTION PIPELINE & STATE LOGIC
    # ==========================================================================

    async def execute_with_backoff(self, api_func: Callable, *args, **kwargs) -> Any:
        """
        The Core Resilience Wrapper.
        Executes an API call using the Token Bucket rate limiter, catches provider
        throttling (429s) or server errors (500s), and applies exponential backoff.
        """
        attempt = 0
        while attempt < self.max_retries:
            try:
                # 1. Respect the Global Rate Limit before making the call
                await self.rate_limiter.acquire()
                
                # 2. Execute the function
                result = await api_func(*args, **kwargs)
                return result

            except Exception as e:
                attempt += 1
                error_msg = str(e).lower()
                
                # Detect Access Denied (403 / AuthorizationFailed)
                if "accessdenied" in error_msg or "authorizationfailed" in error_msg or "403" in error_msg:
                    if self.fail_open:
                        self.logger.warning(f"[{self.tenant.id}] Permission Denied calling {api_func.__name__}. Skipping resource.")
                        return None
                    else:
                        self.logger.error(f"[{self.tenant.id}] FATAL: Access Denied calling {api_func.__name__}.")
                        raise e

                # Detect Throttling (429) or Server Errors (500/503)
                if "throttling" in error_msg or "toomanyrequests" in error_msg or "50" in error_msg:
                    sleep_time = (self.backoff_factor ** attempt)
                    self.logger.warning(f"[{self.tenant.id}] API Throttled/Error on {api_func.__name__}. Retrying in {sleep_time:.2f}s (Attempt {attempt}/{self.max_retries})")
                    await asyncio.sleep(sleep_time)
                    continue
                
                # Unhandled Exceptions
                self.logger.error(f"[{self.tenant.id}] Unexpected failure in {api_func.__name__}: {error_msg}\n{traceback.format_exc()}")
                raise e
        
        # Exhausted Retries
        self.logger.error(f"[{self.tenant.id}] API Exhausted all {self.max_retries} retries for {api_func.__name__}.")
        raise TimeoutError(f"Max retries exceeded for {api_func.__name__}")

    async def check_state_differential(self, resource_arn: str, raw_resource_dict: Dict) -> Tuple[bool, str]:
        """
        State Differential Logic.
        Calculates the SHA256 hash of the JSON resource. If it matches the hash in Redis,
        the resource hasn't changed, and we can skip sending it to Neo4j.
        """
        if not self.use_state_cache or not self.redis_client:
            return True, ""

        try:
            serialized_data = json.dumps(raw_resource_dict, sort_keys=True, default=str)
            current_hash = hashlib.sha256(serialized_data.encode('utf-8')).hexdigest()
            
            cache_key = f"cloudscape:state:{self.tenant.id}:{resource_arn}"
            previous_hash = await self.redis_client.get(cache_key)

            if previous_hash == current_hash:
                return False, current_hash # No change, skip ingestion
            
            # The hash has changed (or is new), update cache (Hardcoded 7 days to avoid config errors)
            ttl_seconds = 7 * 86400
            await self.redis_client.setex(cache_key, ttl_seconds, current_hash)
            return True, current_hash
            
        except RedisError as e:
            self.logger.warning(f"State Cache failure during hash check for {resource_arn}: {e}. Defaulting to full ingest.")
            return True, ""
        except Exception as e:
            self.logger.error(f"Hash calculation error for {resource_arn}: {e}")
            return True, ""

    def format_urm_payload(self, namespace: str, resource_type: str, resource_arn: str, 
                           raw_data: Dict, baseline_risk: float) -> Dict[str, Any]:
        """
        Transforms raw Cloud API JSON into the Universal Resource Model (URM).
        """
        return {
            "metadata": {
                "tenant_id": self.tenant.id,
                "provider": self.tenant.provider,
                "namespace": namespace,
                "resource_type": resource_type,
                "arn": resource_arn,
                "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                "baseline_risk_score": baseline_risk
            },
            "properties": raw_data,
            "tags": raw_data.get("Tags", raw_data.get("tags", {})) 
        }

    # --------------------------------------------------------------------------
    # ABSTRACT METHODS
    # --------------------------------------------------------------------------
    
    @abc.abstractmethod
    async def test_connection(self) -> bool:
        """Validates credentials and endpoint connectivity."""
        pass

    @abc.abstractmethod
    async def run_full_discovery(self) -> List[Dict[str, Any]]:
        """Reads registry, iterates services, applies state diff, returns URM."""
        pass
    
    async def cleanup(self):
        """Gracefully closes connections (like the Redis pool)."""
        if self.redis_client:
            await self.redis_client.close()