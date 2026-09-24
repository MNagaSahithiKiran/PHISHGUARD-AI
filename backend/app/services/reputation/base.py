import abc
import hashlib
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from app.services.reputation.schemas import ProviderResult, ReputationStatus, ReputationEvidenceItem


class ReputationProvider(abc.ABC):
    name: str = "base"
    evidence_type: str = "generic"

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the provider has all required credentials/configurations."""
        pass

    @abc.abstractmethod
    async def query(self, url: str, domain: str) -> ProviderResult:
        """Executes query against external provider."""
        pass

    def compute_evidence_hash(self, payload: Dict[str, Any]) -> str:
        """Generates SHA-256 fingerprint of evidence data."""
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def create_evidence_item(self, result: ProviderResult, source_url: Optional[str] = None) -> ReputationEvidenceItem:
        """Converts ProviderResult into auditable ledger item."""
        data_to_hash = {
            "provider": self.name,
            "status": result.status.value,
            "value": result.summary,
            "details": result.details,
            "query": result.query,
        }
        return ReputationEvidenceItem(
            provider=self.name,
            evidence_type=self.evidence_type,
            status=result.status.value,
            value=result.summary,
            confidence=result.confidence,
            source_url=source_url,
            observed_at=result.timestamp,
            evidence_hash=self.compute_evidence_hash(data_to_hash),
            raw_reference=json.dumps(result.details, default=str) if result.details else None,
        )
