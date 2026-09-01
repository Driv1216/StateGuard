from __future__ import annotations

from typing import Any

import numpy as np

from .models import BankTransaction, Candidate, MerchantLedgerRecord, SettlementGroup


MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
SEMANTIC_TOP_K = 3
DEVICE = "cpu"


def load_model() -> Any:
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as exc:
        raise RuntimeError(
            "The hybrid benchmark requires the real sentence-transformers dependency. "
            "Install spike/requirements.txt; no fallback result will be reported."
        ) from exc
    return SentenceTransformer(MODEL_NAME, device=DEVICE)


def _candidate_text(settlement: SettlementGroup, bank: BankTransaction) -> str:
    return " | ".join(
        part
        for part in (
            settlement.description,
            " ".join(settlement.references),
            bank.description,
            bank.reference,
        )
        if part
    )


def generate_semantic_candidates(
    ledger_records: list[MerchantLedgerRecord],
    settlements: dict[str, SettlementGroup],
    bank_transactions: list[BankTransaction],
    unresolved_ledger_ids: set[str],
    model: Any,
    top_k: int = SEMANTIC_TOP_K,
) -> dict[str, list[Candidate]]:
    results: dict[str, list[Candidate]] = {ledger_id: [] for ledger_id in unresolved_ledger_ids}
    if not unresolved_ledger_ids:
        return results

    pair_rows = [
        (settlement, bank)
        for settlement in settlements.values()
        for bank in bank_transactions
    ]
    documents = [_candidate_text(settlement, bank) for settlement, bank in pair_rows]
    document_vectors = np.asarray(
        model.encode(documents, normalize_embeddings=True, show_progress_bar=False),
        dtype=float,
    )

    for ledger in ledger_records:
        if ledger.ledger_id not in unresolved_ledger_ids:
            continue
        query = " | ".join(part for part in (ledger.description, ledger.reference) if part)
        query_vector = np.asarray(
            model.encode([query], normalize_embeddings=True, show_progress_bar=False)[0],
            dtype=float,
        )
        scores = document_vectors @ query_vector
        ranked = np.argsort(-scores, kind="stable")[:top_k]
        for pair_index in ranked:
            settlement, bank = pair_rows[int(pair_index)]
            results[ledger.ledger_id].append(
                Candidate(
                    ledger_id=ledger.ledger_id,
                    settlement_id=settlement.settlement_id,
                    bank_id=bank.bank_id,
                    source="semantic",
                    semantic_score=float(scores[int(pair_index)]),
                )
            )
    return results

