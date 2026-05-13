"""
BaseCheck — abstract base class for all Stratus check modules.
"""

from abc import ABC, abstractmethod
from typing import List

import boto3


class BaseCheck(ABC):
    """
    Each subclass implements run() and returns a list of Finding objects.
    Boto3 errors for missing permissions are caught and silently skipped
    so a scan doesn't abort on partially-credentialed accounts.
    """

    @property
    @abstractmethod
    def service(self) -> str:
        """AWS service name (e.g. 'IAM', 'S3')."""

    @abstractmethod
    def run(self, session: boto3.Session, region: str) -> List:
        """
        Execute all checks for this module.

        Args:
            session: boto3.Session configured with credentials/profile
            region:  AWS region string (e.g. 'us-east-1')

        Returns:
            List[Finding]
        """
