import asyncio
import logging
import traceback
from typing import Any, Dict, List

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

from engines.base_engine import BaseDiscoveryEngine
from core.config import config, TenantConfig

# ==============================================================================
# AWS ENTERPRISE DISCOVERY ENGINE (NEXUS 5.0 AETHER)
# ==============================================================================
# Handles high-concurrency, paginated data extraction from AWS/LocalStack.
# Wraps all synchronous Boto3 network I/O in asyncio.to_thread to prevent 
# Event Loop blocking. Implements isolated fault domains per service and 
# forces S3 Path-Style addressing for local Docker mesh discovery.
# ==============================================================================

class AWSEngine(BaseDiscoveryEngine):
    def __init__(self, tenant: TenantConfig):
        super().__init__(tenant)
        self.logger = logging.getLogger(f"Cloudscape.Engines.AWS.[{self.tenant.id}]")

    # ==========================================================================
    # AUTHENTICATION & CONNECTIVITY
    # ==========================================================================

    async def test_connection(self) -> bool:
        """
        Validates the AWS or LocalStack STS token.
        Dynamically updates the tenant credentials state in memory to ensure 
        subsequent ARNs are constructed with the correct Account ID.
        """
        self.logger.info("Testing AWS STS Connectivity...")
        try:
            client_kwargs = self.get_aws_client_kwargs()
            sts_client = await asyncio.to_thread(boto3.client, 'sts', **client_kwargs)
            
            identity = await self.execute_with_backoff(
                asyncio.to_thread, sts_client.get_caller_identity
            )
            
            account_id = identity.get('Account')
            self.logger.debug(f"[{self.tenant.id}] STS Auth Success. Account: {account_id}")
            
            # Dynamically state-map the account ID
            self.tenant.credentials.aws_account_id = account_id
            return True
            
        except (ClientError, BotoCoreError) as e:
            self.logger.error(f"AWS STS Authentication failed: {e}")
            return False
        except Exception as e:
            self.logger.critical(f"Unexpected connection error during AWS init: {e}\n{traceback.format_exc()}")
            return False

    # ==========================================================================
    # UTILITY METHODS
    # ==========================================================================

    def _normalize_tags(self, raw_tags: List[Dict[str, str]]) -> Dict[str, str]:
        """
        Converts standard AWS tag lists [{'Key': 'Env', 'Value': 'Prod'}] 
        into a flat dictionary {'Env': 'Prod'} for Neo4j compatibility.
        """
        if not raw_tags or not isinstance(raw_tags, list):
            return {}
        return {tag.get('Key', ''): tag.get('Value', '') for tag in raw_tags if 'Key' in tag}

    async def _fetch_service_paginated(self, client: Any, paginator_name: str, 
                                       operation_name: str, response_key: str, 
                                       **kwargs) -> List[Dict]:
        """
        Generic asynchronous paginator wrapper. 
        Respects the max_pagination_depth circuit breaker to prevent memory exhaustion.
        """
        results = []
        try:
            paginator = client.get_paginator(paginator_name)
            page_iterator = await asyncio.to_thread(paginator.paginate, **kwargs)
            
            page_count = 0
            max_depth = getattr(config.settings.crawling, 'max_pagination_depth', 50)
            
            # Iterate through the synchronous generator in a thread-safe manner
            for page in await asyncio.to_thread(list, page_iterator):
                if page_count >= max_depth:
                    self.logger.warning(f"[{self.tenant.id}] Pagination circuit breaker tripped at depth {max_depth} for {operation_name}.")
                    break
                
                items = page.get(response_key, [])
                results.extend(items)
                page_count += 1
                
            return results
        except Exception as e:
            self.logger.error(f"Failed to fetch paginated data for {operation_name}: {e}")
            raise

    # ==========================================================================
    # NETWORK FABRIC EXTRACTION (THE MISSING LAYER)
    # ==========================================================================

    async def _extract_vpcs(self, client_kwargs: Dict, baseline_risk: float) -> List[Dict]:
        """Extracts Virtual Private Clouds (The Network Backbone)."""
        payloads = []
        try:
            ec2_client = await asyncio.to_thread(boto3.client, 'ec2', **client_kwargs)
            vpcs = await self.execute_with_backoff(
                self._fetch_service_paginated, ec2_client, 'describe_vpcs', 'describe_vpcs', 'Vpcs'
            )
            
            account_id = self.tenant.credentials.aws_account_id
            region = client_kwargs.get("region_name", "us-east-1")
            
            for vpc in vpcs:
                vpc_id = vpc.get("VpcId")
                arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
                
                vpc["tags"] = self._normalize_tags(vpc.get("Tags", []))
                
                has_changed, current_hash = await self.check_state_differential(arn, vpc)
                if not has_changed: continue
                    
                vpc["_state_hash"] = current_hash
                payloads.append(self.format_urm_payload("aws.ec2", "VPC", arn, vpc, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] VPC extraction failed: {e}")
        return payloads

    async def _extract_subnets(self, client_kwargs: Dict, baseline_risk: float) -> List[Dict]:
        """Extracts Network Subnets."""
        payloads = []
        try:
            ec2_client = await asyncio.to_thread(boto3.client, 'ec2', **client_kwargs)
            subnets = await self.execute_with_backoff(
                self._fetch_service_paginated, ec2_client, 'describe_subnets', 'describe_subnets', 'Subnets'
            )
            
            account_id = self.tenant.credentials.aws_account_id
            region = client_kwargs.get("region_name", "us-east-1")
            
            for subnet in subnets:
                subnet_id = subnet.get("SubnetId")
                arn = f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}"
                
                subnet["tags"] = self._normalize_tags(subnet.get("Tags", []))
                
                has_changed, current_hash = await self.check_state_differential(arn, subnet)
                if not has_changed: continue
                    
                subnet["_state_hash"] = current_hash
                payloads.append(self.format_urm_payload("aws.ec2", "Subnet", arn, subnet, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] Subnet extraction failed: {e}")
        return payloads

    async def _extract_security_groups(self, client_kwargs: Dict, baseline_risk: float) -> List[Dict]:
        """Extracts VPC Security Groups for Network Exposure math."""
        payloads = []
        try:
            ec2_client = await asyncio.to_thread(boto3.client, 'ec2', **client_kwargs)
            sgs = await self.execute_with_backoff(
                self._fetch_service_paginated, ec2_client, 'describe_security_groups', 'describe_security_groups', 'SecurityGroups'
            )
            
            account_id = self.tenant.credentials.aws_account_id
            region = client_kwargs.get("region_name", "us-east-1")
            
            for sg in sgs:
                sg_id = sg.get("GroupId")
                arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
                
                sg["tags"] = self._normalize_tags(sg.get("Tags", []))
                
                has_changed, current_hash = await self.check_state_differential(arn, sg)
                if not has_changed: continue
                    
                sg["_state_hash"] = current_hash
                payloads.append(self.format_urm_payload("aws.ec2", "SecurityGroup", arn, sg, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] Security Group extraction failed: {e}")
        return payloads

    # ==========================================================================
    # COMPUTE & DATA EXTRACTION PIPELINES
    # ==========================================================================

    async def _extract_s3_buckets(self, client_kwargs: Dict, baseline_risk: float) -> List[Dict]:
        """
        Extracts S3 Buckets.
        [AETHER FIX] Forces Path-Style addressing so LocalStack doesn't drop the connection.
        """
        payloads = []
        try:
            # Overwrite config for path-style addressing required by Local Docker Mesh
            s3_config = Config(s3={'addressing_style': 'path'}, signature_version='s3v4')
            s3_client = await asyncio.to_thread(boto3.client, 's3', config=s3_config, **client_kwargs)
            
            # list_buckets does not use a paginator
            response = await self.execute_with_backoff(asyncio.to_thread, s3_client.list_buckets)
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                name = bucket.get("Name")
                arn = f"arn:aws:s3:::{name}"
                bucket["_secondary_metadata"] = {}
                
                # Fetch Public Access Block (Vulnerability check)
                try:
                    pab_resp = await self.execute_with_backoff(asyncio.to_thread, s3_client.get_public_access_block, Bucket=name)
                    bucket["_secondary_metadata"]["get_public_access_block"] = pab_resp.get("PublicAccessBlockConfiguration", {})
                except Exception: pass # Expected if not explicitly set

                # Fetch Tagging
                try:
                    tags_resp = await self.execute_with_backoff(asyncio.to_thread, s3_client.get_bucket_tagging, Bucket=name)
                    bucket["tags"] = self._normalize_tags(tags_resp.get("TagSet", []))
                except Exception:
                    bucket["tags"] = {}

                has_changed, current_hash = await self.check_state_differential(arn, bucket)
                if not has_changed: continue
                    
                bucket["_state_hash"] = current_hash
                payloads.append(self.format_urm_payload("aws.s3", "Bucket", arn, bucket, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] S3 Bucket extraction failed: {e}")
        return payloads

    async def _extract_iam_roles(self, client_kwargs: Dict, baseline_risk: float) -> List[Dict]:
        """Extracts IAM Roles and fetches attached policies (Identity Fabric source)."""
        payloads = []
        try:
            iam_client = await asyncio.to_thread(boto3.client, 'iam', **client_kwargs)
            roles = await self.execute_with_backoff(
                self._fetch_service_paginated, iam_client, 'list_roles', 'list_roles', 'Roles'
            )
            
            for role in roles:
                arn = role.get("Arn")
                role_name = role.get("RoleName")
                
                try:
                    attached_policies_resp = await self.execute_with_backoff(
                        asyncio.to_thread, iam_client.list_attached_role_policies, RoleName=role_name
                    )
                    role["_secondary_metadata"] = {"AttachedPolicies": attached_policies_resp.get("AttachedPolicies", [])}
                except Exception as meta_err:
                    self.logger.debug(f"Could not fetch policies for role {role_name}: {meta_err}")

                role["tags"] = self._normalize_tags(role.get("Tags", []))
                
                has_changed, current_hash = await self.check_state_differential(arn, role)
                if not has_changed: continue
                    
                role["_state_hash"] = current_hash
                payloads.append(self.format_urm_payload("aws.iam", "Role", arn, role, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] IAM Role extraction failed: {e}")
        return payloads

    async def _extract_ec2_instances(self, client_kwargs: Dict, baseline_risk: float) -> List[Dict]:
        """Extracts EC2 Compute instances."""
        payloads = []
        try:
            ec2_client = await asyncio.to_thread(boto3.client, 'ec2', **client_kwargs)
            reservations = await self.execute_with_backoff(
                self._fetch_service_paginated, ec2_client, 'describe_instances', 'describe_instances', 'Reservations'
            )
            
            account_id = self.tenant.credentials.aws_account_id
            region = client_kwargs.get("region_name", "us-east-1")
            
            for res in reservations:
                for instance in res.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
                    
                    instance["tags"] = self._normalize_tags(instance.get("Tags", []))
                    
                    has_changed, current_hash = await self.check_state_differential(arn, instance)
                    if not has_changed: continue
                        
                    instance["_state_hash"] = current_hash
                    payloads.append(self.format_urm_payload("aws.ec2", "Instance", arn, instance, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] EC2 Instance extraction failed: {e}")
        return payloads

    async def _extract_rds_instances(self, client_kwargs: Dict, baseline_risk: float) -> List[Dict]:
        """Extracts Relational Database Service instances."""
        payloads = []
        try:
            rds_client = await asyncio.to_thread(boto3.client, 'rds', **client_kwargs)
            db_instances = await self.execute_with_backoff(
                self._fetch_service_paginated, rds_client, 'describe_db_instances', 'describe_db_instances', 'DBInstances'
            )
            
            for db in db_instances:
                arn = db.get("DBInstanceArn")
                db["tags"] = self._normalize_tags(db.get("TagList", []))
                
                has_changed, current_hash = await self.check_state_differential(arn, db)
                if not has_changed: continue
                    
                db["_state_hash"] = current_hash
                payloads.append(self.format_urm_payload("aws.rds", "DBInstance", arn, db, baseline_risk))
        except Exception as e:
            self.logger.error(f"[{self.tenant.id}] RDS extraction failed: {e}")
        return payloads

    # ==========================================================================
    # MASTER EXECUTION PIPELINE
    # ==========================================================================

    async def run_full_discovery(self) -> List[Dict[str, Any]]:
        """
        The main ingestion pipeline. 
        Asynchronously executes isolated service extraction methods based on the 
        Universal Service Registry definitions. If registry is missing keys, 
        defaults to Deep Scan mode to ensure full infrastructure mapping.
        """
        self.logger.info(f"[{self.tenant.id}] Initiating Full AWS Telemetry Extraction...")
        total_payloads = []
        
        client_kwargs = self.get_aws_client_kwargs()
        aws_registry = config.service_registry.get("aws", {})
        
        tasks = []
        
        # --- IDENTITY & ACCESS ---
        risk = aws_registry.get("iam_role", {}).get("baseline_risk_score", 0.5)
        tasks.append(self._extract_iam_roles(client_kwargs, risk))
            
        # --- STORAGE & DATA ---
        risk = aws_registry.get("s3_bucket", {}).get("baseline_risk_score", 0.3)
        tasks.append(self._extract_s3_buckets(client_kwargs, risk))

        risk = aws_registry.get("rds_instance", {}).get("baseline_risk_score", 0.8)
        tasks.append(self._extract_rds_instances(client_kwargs, risk))
            
        # --- COMPUTE ---
        risk = aws_registry.get("ec2_instance", {}).get("baseline_risk_score", 0.4)
        tasks.append(self._extract_ec2_instances(client_kwargs, risk))
            
        # --- NETWORK FABRIC ---
        risk = aws_registry.get("vpc", {}).get("baseline_risk_score", 0.1)
        tasks.append(self._extract_vpcs(client_kwargs, risk))
        
        risk = aws_registry.get("subnet", {}).get("baseline_risk_score", 0.1)
        tasks.append(self._extract_subnets(client_kwargs, risk))

        risk = aws_registry.get("security_group", {}).get("baseline_risk_score", 0.2)
        tasks.append(self._extract_security_groups(client_kwargs, risk))

        # Wait for all fault-isolated pipelines to complete concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"[{self.tenant.id}] A service extraction task crashed: {result}")
            elif isinstance(result, list):
                total_payloads.extend(result)

        self.logger.info(f"[{self.tenant.id}] Discovery Complete. {len(total_payloads)} fresh nodes acquired.")
        return total_payloads