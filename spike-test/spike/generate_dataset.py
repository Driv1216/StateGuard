from __future__ import annotations

import csv
import json
import random
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path


DATASET_SEED = 20260821
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    category: str
    expected_status: str
    description: str


CASE_SPECS = tuple(
    [
        CaseSpec(f"CASE-CLEAN-{index:02d}", "clean", "VERIFIED", f"Online sales batch {index:02d}")
        for index in range(1, 16)
    ]
    + [
        CaseSpec(
            f"CASE-NORMALIZED-{index:02d}",
            "normalized",
            "VERIFIED",
            f"Normalized payout batch {index:02d}",
        )
        for index in range(1, 6)
    ]
    + [
        CaseSpec("CASE-SEMANTIC-01", "semantic", "VERIFIED", "Riverfront Arts Festival ticket proceeds"),
        CaseSpec("CASE-SEMANTIC-02", "semantic", "VERIFIED", "Blue Mango Crafts online order payout"),
        CaseSpec("CASE-SEMANTIC-03", "semantic", "VERIFIED", "Northstar Learning workshop enrolments"),
        CaseSpec("CASE-SEMANTIC-04", "semantic", "VERIFIED", "Monsoon Kitchen weekend delivery sales"),
        CaseSpec("CASE-SEMANTIC-05", "semantic", "VERIFIED", "Copper Leaf Studio advance booking receipts"),
    ]
    + [
        CaseSpec(f"CASE-AMBIGUOUS-{index:02d}", "ambiguous", "REVIEW", "Shared marketplace payout")
        for index in range(1, 4)
    ]
    + [
        CaseSpec("CASE-CORRUPTED-01", "corrupted", "EXCEPTION", "Linked payout with unexplained bank shortfall"),
        CaseSpec("CASE-CORRUPTED-02", "corrupted", "EXCEPTION", "Linked payout with mixed component currencies"),
    ]
)


def _opaque_id(rng: random.Random, prefix: str) -> str:
    return f"{prefix}-{rng.getrandbits(48):012X}"


def _money(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.01')):.2f}"


def _semantic_descriptions(entity: str) -> tuple[str, str, str]:
    return (
        f"Expected merchant payout: {entity}",
        f"Razorpay settlement covering {entity.lower()}",
        f"NEFT credit received for {entity.lower()}",
    )


def build_dataset(seed: int = DATASET_SEED) -> tuple[list[dict], list[dict], list[dict], dict]:
    rng = random.Random(seed)
    ledger_rows: list[dict] = []
    recon_rows: list[dict] = []
    bank_rows: list[dict] = []
    truth_cases: list[dict] = []
    start = date(2026, 1, 5)

    for index, spec in enumerate(CASE_SPECS):
        ledger_id = _opaque_id(rng, "LED")
        settlement_id = _opaque_id(rng, "SET")
        bank_id = _opaque_id(rng, "BNK")
        component_prefix = _opaque_id(rng, "CMP")
        booked_on = start + timedelta(days=index * 3)
        settled_on = booked_on + timedelta(days=1)
        posted_on = settled_on + timedelta(days=1)

        net = Decimal(20000 + index * 1731) + Decimal(f"0.{(index * 17) % 100:02d}")
        if spec.category == "ambiguous":
            net = Decimal("77777.77")
            booked_on = date(2026, 4, 20)
            settled_on = date(2026, 4, 21)
            posted_on = date(2026, 4, 22)
        if spec.case_id == "CASE-CORRUPTED-01":
            net = Decimal("48731.00")
        if spec.case_id == "CASE-CORRUPTED-02":
            net = Decimal("62420.00")

        fee = Decimal(145 + (index % 5) * 11)
        tax = (fee * Decimal("0.18")).quantize(Decimal("0.01"))
        gross = net + fee + tax
        base_ref = f"UTR{rng.getrandbits(40):010X}"
        ledger_ref = recon_ref = bank_ref = base_ref
        ledger_desc = recon_desc = bank_desc = spec.description

        if spec.category == "normalized":
            tail = base_ref[3:]
            ledger_ref = f"utr {tail[:4]} {tail[4:]}"
            recon_ref = f"UTR-{tail[:5]}-{tail[5:]}"
            bank_ref = f"utr/{tail}"
        elif spec.category == "semantic":
            ledger_ref = _opaque_id(rng, "MER")
            recon_ref = _opaque_id(rng, "RZP")
            bank_ref = _opaque_id(rng, "NEFT")
            ledger_desc, recon_desc, bank_desc = _semantic_descriptions(spec.description)
        elif spec.category == "ambiguous":
            ledger_ref = recon_ref = bank_ref = "BATCH-SHARED-AMB"
            ledger_desc = recon_desc = bank_desc = "Marketplace combined settlement"

        bank_amount = net
        component_currencies = ["INR", "INR", "INR"]
        if spec.case_id == "CASE-CORRUPTED-01":
            bank_amount = net - Decimal("200.00")
        elif spec.case_id == "CASE-CORRUPTED-02":
            component_currencies[1] = "USD"

        ledger_rows.append(
            {
                "ledger_id": ledger_id,
                "booked_on": booked_on.isoformat(),
                "amount": _money(net),
                "currency": "INR",
                "direction": "CREDIT",
                "reference": ledger_ref,
                "description": ledger_desc,
            }
        )
        for suffix, component_type, amount, currency, description in (
            ("C", "CREDIT", gross, component_currencies[0], recon_desc),
            ("F", "DEBIT", fee, component_currencies[1], "Explicit processing fee"),
            ("T", "DEBIT", tax, component_currencies[2], "Explicit tax debit"),
        ):
            recon_rows.append(
                {
                    "component_id": f"{component_prefix}-{suffix}",
                    "settlement_id": settlement_id,
                    "settled_on": settled_on.isoformat(),
                    "component_type": component_type,
                    "amount": _money(amount),
                    "currency": currency,
                    "reference": recon_ref,
                    "description": description,
                }
            )
        bank_rows.append(
            {
                "bank_id": bank_id,
                "posted_on": posted_on.isoformat(),
                "amount": _money(bank_amount),
                "currency": "INR",
                "direction": "CREDIT",
                "reference": bank_ref,
                "description": bank_desc,
            }
        )
        truth_cases.append(
            {
                "case_id": spec.case_id,
                "category": spec.category,
                "ledger_id": ledger_id,
                "settlement_id": settlement_id,
                "bank_id": bank_id,
                "expected_status": spec.expected_status,
            }
        )

    rng.shuffle(ledger_rows)
    rng.shuffle(recon_rows)
    rng.shuffle(bank_rows)
    truth = {
        "schema_version": 1,
        "dataset_seed": seed,
        "counts": {"clean": 15, "normalized": 5, "semantic": 5, "ambiguous": 3, "corrupted": 2},
        "messy_categories": ["normalized", "semantic"],
        "cases": truth_cases,
    }
    return ledger_rows, recon_rows, bank_rows, truth


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def generate(fixtures_dir: Path = FIXTURES_DIR, seed: int = DATASET_SEED) -> None:
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    ledger, recon, bank, truth = build_dataset(seed)
    _write_csv(fixtures_dir / "merchant_ledger.csv", ledger)
    _write_csv(fixtures_dir / "razorpay_recon.csv", recon)
    _write_csv(fixtures_dir / "bank_statement.csv", bank)
    with (fixtures_dir / "ground_truth.json").open("w", encoding="utf-8") as handle:
        json.dump(truth, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    generate()
    print(f"Generated {len(CASE_SPECS)} cases in {FIXTURES_DIR}")

