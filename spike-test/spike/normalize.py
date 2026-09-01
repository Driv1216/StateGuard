from __future__ import annotations

import csv
import re
import unicodedata
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

from .models import (
    BankTransaction,
    ComponentType,
    Direction,
    MerchantLedgerRecord,
    ReconComponent,
)


DATE_WINDOW_DAYS = 4
BANK_DATE_WINDOW_DAYS = 3
FUZZY_REFERENCE_THRESHOLD = 0.88
AMOUNT_QUANTUM = Decimal("0.01")


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value or "").casefold()
    return " ".join(normalized.split())


def normalize_reference(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", normalize_text(value))


def parse_amount(value: str | Decimal) -> Decimal:
    return Decimal(str(value)).quantize(AMOUNT_QUANTUM, rounding=ROUND_HALF_UP)


def parse_date(value: str) -> date:
    return date.fromisoformat(value)


def load_merchant_ledger(path: Path) -> list[MerchantLedgerRecord]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [
            MerchantLedgerRecord(
                ledger_id=row["ledger_id"],
                booked_on=parse_date(row["booked_on"]),
                amount=parse_amount(row["amount"]),
                currency=row["currency"].upper(),
                direction=Direction(row["direction"].upper()),
                reference=row["reference"],
                description=row["description"],
            )
            for row in csv.DictReader(handle)
        ]


def load_recon_components(path: Path) -> list[ReconComponent]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [
            ReconComponent(
                component_id=row["component_id"],
                settlement_id=row["settlement_id"],
                settled_on=parse_date(row["settled_on"]),
                component_type=ComponentType(row["component_type"].upper()),
                amount=parse_amount(row["amount"]),
                currency=row["currency"].upper(),
                reference=row["reference"],
                description=row["description"],
            )
            for row in csv.DictReader(handle)
        ]


def load_bank_statement(path: Path) -> list[BankTransaction]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [
            BankTransaction(
                bank_id=row["bank_id"],
                posted_on=parse_date(row["posted_on"]),
                amount=parse_amount(row["amount"]),
                currency=row["currency"].upper(),
                direction=Direction(row["direction"].upper()),
                reference=row["reference"],
                description=row["description"],
            )
            for row in csv.DictReader(handle)
        ]


def date_distance(left: date, right: date) -> int:
    return abs((left - right).days)

