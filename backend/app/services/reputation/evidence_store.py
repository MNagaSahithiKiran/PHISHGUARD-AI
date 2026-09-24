from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.scan import ScanEvidence
from app.services.reputation.schemas import ReputationEvidenceItem
from app.core.logging import logger


class EvidenceStore:
    @staticmethod
    async def persist_evidence_ledger(
        db: AsyncSession,
        scan_id: str,
        evidence_items: List[ReputationEvidenceItem],
    ) -> List[ScanEvidence]:
        """
        Stores genuine evidence claims into the scan_evidence database table.
        """
        records: List[ScanEvidence] = []
        for item in evidence_items:
            record = ScanEvidence(
                scan_id=scan_id,
                provider=item.provider,
                evidence_type=item.evidence_type,
                status=item.status,
                value=item.value,
                confidence=item.confidence,
                source_url=item.source_url,
                observed_at=item.observed_at,
                evidence_hash=item.evidence_hash,
                raw_reference=item.raw_reference,
            )
            db.add(record)
            records.append(record)

        try:
            await db.flush()
            logger.info(f"Persisted {len(records)} evidence items for scan {scan_id}")
        except Exception as e:
            logger.error(f"Failed to persist evidence ledger for scan {scan_id}: {e}")

        return records
