import boto3
from moto import mock_aws
import logging

class CloudMockAWS:
    """
    High-fidelity AWS API Simulator using Moto.
    Provides stateful resource management for orchestrator testing.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("CloudScape.Mock.AWS")
        self._mock = mock_aws()

    def start(self):
        """Activates the global Moto interceptor."""
        self._mock.start()
        self.logger.info("Moto AWS API Interceptor: ACTIVE")

    def stop(self):
        """Deactivates the global Moto interceptor."""
        self._mock.stop()
        self.logger.info("Moto AWS API Interceptor: STOPPED")

    def seed_bootstrap_infra(self):
        """Pre-provisions the mock environment with target resources."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="cloudscape-forensic-target")
        
        iam = boto3.client("iam")
        iam.create_role(
            RoleName="CloudScape-Orchestrator-Role",
            AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"Service": "ec2.amazonaws.com"},"Action": "sts:AssumeRole"}]}'
        )
        
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
        
        self.logger.info("Mock AWS Infrastructure: SEEDED (S3, IAM, EC2)")

aws_mock = CloudMockAWS()
