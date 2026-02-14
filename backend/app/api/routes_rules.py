from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/rules", tags=["rules"])


class RuleCandidate(BaseModel):
    id: str
    src: str
    dst: str
    proto: str | None = None
    port: int | None = None
    basis: str | None = None
    from_value: str | None = None
    to_value: str | None = None
    notes: str | None = None


class RuleProposalRequest(BaseModel):
    basis: str
    from_value: str
    to_value: str
    view: str = "original"
    metric: str = "count"


@router.post("/propose")
def propose_rules(payload: RuleProposalRequest) -> Dict[str, Any]:
    # Placeholder: later we will derive from flows table.
    candidates: List[RuleCandidate] = [
        RuleCandidate(
            id="rule-1",
            src=f"{payload.basis}:{payload.from_value}",
            dst=f"{payload.basis}:{payload.to_value}",
            proto="tcp",
            port=443,
            basis=payload.basis,
            from_value=payload.from_value,
            to_value=payload.to_value,
            notes="Placeholder candidate based on top flows.",
        )
    ]
    return {"candidates": [c.model_dump() for c in candidates]}


class ExportCliRequest(BaseModel):
    candidates: List[RuleCandidate]
    target: str = "nftables"


@router.post("/export/cli")
def export_cli(payload: ExportCliRequest):
    # Very simple placeholder text script.
    lines: List[str] = ["# Generated firewall rules (placeholder)"]
    if payload.target == "nftables":
        for c in payload.candidates:
            lines.append(
                f"add rule inet filter forward ip saddr {c.src} ip daddr {c.dst} tcp dport {c.port or 'any'} accept"
            )
    else:
        lines.append(f"# Unknown target {payload.target}, no concrete syntax yet.")

    script = "\n".join(lines) + "\n"
    return {"target": payload.target, "script": script}

