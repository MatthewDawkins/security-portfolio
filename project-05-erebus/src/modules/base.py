from abc import ABC, abstractmethod
from typing import List
import requests
from src.models import Finding


class BaseModule(ABC):
    name: str = ""
    description: str = ""

    def __init__(self, session: requests.Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout

    @abstractmethod
    def run(self, urls: List[str], forms: List[dict]) -> List[Finding]:
        """Run checks and return a list of findings."""
        ...

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.session.get(url, timeout=self.timeout, allow_redirects=False, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.session.post(url, timeout=self.timeout, allow_redirects=False, **kwargs)
