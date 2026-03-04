import os
import json
import logging
import boto3
from botocore.exceptions import ClientError
from azure.storage.blob import BlobServiceClient
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# CLOUDSCAPE NEXUS 5.0 - ENTERPRISE MESH MEGA-SEEDER
# ==============================================================================
# Generates a highly complex, multi-tenant, multi-cloud infrastructure graph.
# Seeds LocalStack (AWS) and Azurite (Azure) with realistic VPCs, IAM Trusts, 
# S3 Data Lakes, RDS Clusters, and Azure Blob Storage tiers.
# ==============================================================================

try:
    from rich.console import Console
    from rich.theme import Theme
    console = Console(theme=Theme({"info": "cyan", "success": "green", "warning": "yellow", "danger": "bold red"}))
except ImportError:
    class DummyConsole:
        def print(self, msg, style=None): print(msg)
    console = DummyConsole()

# --- GLOBAL CONFIGURATION ---
AWS_ENDPOINT = "http://127.0.0.1:4566"
AWS_REGION = "us-east-1"
DUMMY_CREDS = {"aws_access_key_id": "nexus-admin", "aws_secret_access_key": "nexus-secret"}

AZURE_CONN_STR = (
    "DefaultEndpointsProtocol=http;"
    "AccountName=devstoreaccount1;"
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
)

class AWSMeshSeeder:
    def __init__(self):
        self.ec2 = boto3.client('ec2', endpoint_url=AWS_ENDPOINT, region_name=AWS_REGION, **DUMMY_CREDS)
        self.s3 = boto3.client('s3', endpoint_url=AWS_ENDPOINT, region_name=AWS_REGION, **DUMMY_CREDS)
        self.iam = boto3.client('iam', endpoint_url=AWS_ENDPOINT, region_name=AWS_REGION, **DUMMY_CREDS)
        self.rds = boto3.client('rds', endpoint_url=AWS_ENDPOINT, region_name=AWS_REGION, **DUMMY_CREDS)

    def generate_vpc_topology(self, project_name: str, cidr: str) -> dict:
        """Provisions a realistic network layer: VPC -> Subnets -> Security Groups"""
        console.print(f"[{project_name}] Forging Network Fabric ({cidr})...", style="info")
        try:
            # 1. Create VPC
            vpc = self.ec2.create_vpc(CidrBlock=cidr)
            vpc_id = vpc['Vpc']['VpcId']
            self.ec2.create_tags(Resources=[vpc_id], Tags=[{'Key': 'Name', 'Value': f'{project_name}-vpc'}, {'Key': 'Project', 'Value': project_name}])

            # 2. Create Subnets (Public & Private)
            pub_sub = self.ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr.replace("0.0/16", "1.0/24"))
            priv_sub = self.ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr.replace("0.0/16", "2.0/24"))
            
            self.ec2.create_tags(Resources=[pub_sub['Subnet']['SubnetId']], Tags=[{'Key': 'Tier', 'Value': 'Public'}])
            self.ec2.create_tags(Resources=[priv_sub['Subnet']['SubnetId']], Tags=[{'Key': 'Tier', 'Value': 'Private'}])

            # 3. Create Security Group
            sg = self.ec2.create_security_group(GroupName=f'{project_name}-sg-web', Description=f'Web traffic for {project_name}', VpcId=vpc_id)
            sg_id = sg['GroupId']
            
            # Add Ingress rules (Simulating a vulnerability if project is WEB)
            if "WEB" in project_name:
                self.ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
                    {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}, # Intentional High Risk
                    {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ])
            
            return {"vpc_id": vpc_id, "subnets": [pub_sub['Subnet']['SubnetId'], priv_sub['Subnet']['SubnetId']], "sg_id": sg_id}
        except Exception as e:
            console.print(f"[{project_name}] Network generation skipped: {e}", style="warning")
            return {}

    def generate_data_lakes(self):
        """Provisions S3 buckets with complex multi-level tagging and access configurations"""
        console.print("Forging S3 Data Lakes...", style="info")
        buckets = [
            {"name": "proj-fin-01-pci-vault-secure", "tags": {"DataClass": "PCI", "Environment": "Prod", "Risk": "Critical"}},
            {"name": "proj-web-02-public-assets", "tags": {"DataClass": "Public", "Environment": "Prod", "Risk": "Low"}},
            {"name": "proj-shr-03-central-logging", "tags": {"DataClass": "Internal", "Retention": "7Years"}},
            {"name": "proj-dr-05-backup-unencrypted", "tags": {"DataClass": "Proprietary", "Vulnerability": "Unencrypted"}}
        ]
        
        for b in buckets:
            try:
                self.s3.create_bucket(Bucket=b["name"])
                self.s3.put_bucket_tagging(Bucket=b["name"], Tagging={'TagSet': [{'Key': k, 'Value': v} for k, v in b["tags"].items()]})
                console.print(f"  + S3 Bucket Materialized: {b['name']}", style="success")
            except Exception as e:
                pass # Bucket likely exists

    def generate_identity_fabric(self):
        """Provisions complex IAM trusts and Cross-Cloud Shadow Admins"""
        console.print("Forging IAM Identity Fabric (Shadow Admins)...", style="info")
        
        # 1. Standard Dev Role
        try:
            self.iam.create_role(
                RoleName='PROJ-WEB-02-Developer-Role',
                AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"Service": "ec2.amazonaws.com"},"Action": "sts:AssumeRole"}]}'
            )
            self.iam.attach_role_policy(RoleName='PROJ-WEB-02-Developer-Role', PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess')
        except ClientError: pass

        # 2. The Cross-Cloud Vulnerability (Aether Detection Target)
        try:
            self.iam.create_role(
                RoleName='Azure-Federated-Admin-Role',
                AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"AWS": "*"},"Action": "sts:AssumeRole"}]}'
            )
            # Injecting the exact escalation path Aether is looking for
            self.iam.put_role_policy(
                RoleName='Azure-Federated-Admin-Role',
                PolicyName='CrossCloudEscalationPolicy',
                PolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": ["iam:PassRole", "ec2:RunInstances", "s3:*"],"Resource": "*"}]}'
            )
            console.print("  + [ATTACK PATH] Provisioned: Azure-Federated-Admin-Role", style="danger")
        except ClientError: pass

    def generate_databases(self):
        """Provisions RDS configurations (simulated in LocalStack)"""
        console.print("Forging RDS Database Clusters...", style="info")
        try:
            self.rds.create_db_instance(
                DBInstanceIdentifier='proj-fin-01-transaction-db',
                AllocatedStorage=20,
                DBInstanceClass='db.t3.micro',
                Engine='postgres',
                MasterUsername='admin',
                MasterUserPassword='supersecretpassword',
                PubliclyAccessible=False,
                StorageEncrypted=True,
                Tags=[{'Key': 'Project', 'Value': 'FIN-01'}, {'Key': 'Contains', 'Value': 'PII'}]
            )
            
            self.rds.create_db_instance(
                DBInstanceIdentifier='proj-web-02-session-db',
                AllocatedStorage=10,
                DBInstanceClass='db.t3.micro',
                Engine='mysql',
                MasterUsername='admin',
                MasterUserPassword='supersecretpassword',
                PubliclyAccessible=True, # Vulnerability Target
                StorageEncrypted=False,  # Vulnerability Target
                Tags=[{'Key': 'Project', 'Value': 'WEB-02'}]
            )
            console.print("  + RDS Instances Materialized.", style="success")
        except Exception as e:
            pass

class AzureMeshSeeder:
    def __init__(self):
        self.blob_client = BlobServiceClient.from_connection_string(AZURE_CONN_STR)

    def generate_storage_hierarchy(self):
        """Provisions Azure Blob Containers with rich metadata simulating Enterprise structures."""
        console.print("Forging Azure Storage Fabric (Azurite)...", style="info")
        
        containers = [
            {"name": "proj-azure-04-legal-holds", "meta": {"Department": "Legal", "RetentionPolicy": "Indefinite", "RiskTier": "Tier0"}},
            {"name": "proj-azure-04-public-blobs", "meta": {"AccessTier": "Hot", "Exposure": "Public", "Data": "Marketing"}},
            {"name": "proj-azure-04-vm-diagnostics", "meta": {"AutoDelete": "30Days", "System": "Core"}},
            {"name": "cross-cloud-exchange-buffer", "meta": {"FederatedWith": "AWS", "Role": "Azure-Federated-Admin-Role"}} # The conceptual bridge
        ]
        
        for c in containers:
            try:
                container_client = self.blob_client.get_container_client(c["name"])
                if not container_client.exists():
                    container_client.create_container(metadata=c["meta"])
                    console.print(f"  + Blob Container Materialized: {c['name']}", style="success")
            except Exception as e:
                console.print(f"  - Failed Azure Container {c['name']}: {e}", style="warning")

# ==============================================================================
# ORCHESTRATION
# ==============================================================================

def execute_mega_seed():
    console.print("\n" + "="*80, style="info")
    console.print("    IGNITING NEXUS 5.0 AETHER MEGA-SEEDER", style="bold cyan")
    console.print("="*80 + "\n", style="info")

    aws = AWSMeshSeeder()
    azure = AzureMeshSeeder()

    # 1. Build AWS Network Topologies
    aws.generate_vpc_topology("PROJ-FIN-01", "10.1.0.0/16")
    aws.generate_vpc_topology("PROJ-WEB-02", "10.2.0.0/16")
    aws.generate_vpc_topology("PROJ-SHR-03", "10.3.0.0/16")
    
    # 2. Build AWS Compute & Data Layers
    aws.generate_data_lakes()
    aws.generate_databases()
    aws.generate_identity_fabric()

    # 3. Build Azure Storage Layer
    azure.generate_storage_hierarchy()

    console.print("\n" + "="*80, style="success")
    console.print("    [✓] MULTI-CLOUD INFRASTRUCTURE SEEDING COMPLETE", style="bold green")
    console.print("    The Matrix is Alive. Ready for Nexus Discovery.", style="green")
    console.print("    Run: python main.py --scan", style="bold yellow")
    console.print("="*80 + "\n", style="success")

if __name__ == "__main__":
    execute_mega_seed()