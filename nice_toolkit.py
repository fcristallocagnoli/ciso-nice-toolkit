#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CISO Decision Support System (DSS) — NICE Framework Toolkit
Práctica 1 · Dirección y Gestión de la Ciberseguridad
============================================================
Subcommands
-----------
  graph       Export edges TSV for inspection
  gap         Gap analysis between current and target roles
  recommend   Greedy multi-objective team recommendation (SOC / GRC)
  plan        Full 2-year CISO plan: gap + recommendation + risk + dashboard
  risk        Risk scenario simulation (% mitigation per scenario)
"""

import argparse
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen

URL_DEFAULT = (
    "https://csrc.nist.gov/csrc/media/Projects/cprt/documents/nice/"
    "cprt_SP_800_181_2_1_0_12-11-2025.json"
)

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Node:
    id: str  # element_identifier
    type: str  # element_type
    title: str  # title
    text: str  # text


@dataclass
class RoleCost:
    role_id: str
    title: str
    category: str  # PD / DD / OG / IO / IN / OM
    hire_cost: float  # annual salary (USD)
    training_cost: float  # one-time upskill cost
    outsource_cost: float  # annual external service cost
    time_to_hire_months: int
    cert_bonus_cost: float  # certifications required
    criticality_score: float  # 0-10
    risk_impact_pct: float  # % risk reduction contribution
    action: str = "hire"  # hire | train | outsource


# ─────────────────────────────────────────────────────────────────────────────
# Load / parse NICE JSON
# ─────────────────────────────────────────────────────────────────────────────


def load_payload(url: str) -> Dict[str, Any]:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (NICE-Toolkit)"})
    with urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def load_nodes(url: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    data = load_payload(url)
    # exact schema you pasted:
    # data["response"]["elements"]["elements"] is the node list
    root = data["response"]["elements"]
    elems = root["elements"]
    if not isinstance(elems, list):
        raise ValueError("Expected response.elements.elements to be a list")
    return (
        elems,
        root,
    )  # root contains documents, relationship_types, and (elsewhere) relationships


def build_node_index(elements: List[Dict[str, Any]]) -> Dict[str, Node]:
    idx: Dict[str, Node] = {}
    for e in elements:
        if not isinstance(e, dict):
            continue
        eid = e.get("element_identifier")
        etype = e.get("element_type")
        if not isinstance(eid, str) or not isinstance(etype, str):
            continue
        idx[eid] = Node(
            id=eid,
            type=etype,
            title=e.get("title", "") if isinstance(e.get("title"), str) else "",
            text=e.get("text", "") if isinstance(e.get("text"), str) else "",
        )
    return idx


# ─────────────────────────────────────────────────────────────────────────────
# Graph construction
# ─────────────────────────────────────────────────────────────────────────────


def looks_like_id(s: str) -> bool:
    # Work role IDs like OG-WRL-001, PD-WRL-007; others like T0001, S0001, K0001, etc.
    return bool(re.match(r"^[A-Z]{2}-WRL-\d{3}$", s) or re.match(r"^[A-Z]\d{3,6}$", s))


def find_relationship_lists(obj: Any) -> List[List[Dict[str, Any]]]:
    """
    Search the whole JSON subtree (root) for list-of-dicts that look like relationships:
    dicts containing (source, target) IDs.
    """
    candidates: List[List[Dict[str, Any]]] = []

    def walk(x: Any):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            # relationship list heuristic: list of dicts with 2+ id-like fields
            if x and all(isinstance(it, dict) for it in x):
                # check first few items
                sample = x[:5]
                score = sum(
                    1
                    for it in sample
                    if len(
                        [
                            vv
                            for vv in it.values()
                            if isinstance(vv, str) and looks_like_id(vv)
                        ]
                    )
                    >= 2
                )
                if score >= max(1, len(sample) // 2):
                    candidates.append(x)  # type: ignore
            for it in x:
                walk(it)

    walk(obj)
    return candidates


def build_edges(
    root: Dict[str, Any], node_index: Dict[str, Node]
) -> Set[Tuple[str, str]]:
    """
    Build directed edges (src_id, dst_id) using *actual relationship objects* discovered in JSON.
    We only accept edges where both ends are known node identifiers.
    """
    rel_lists = find_relationship_lists(root)

    edges: Set[Tuple[str, str]] = set()

    def extract_pairs(rel: Dict[str, Any]) -> List[Tuple[str, str]]:
        # try common field names
        keys_src = [
            "source",
            "source_id",
            "source_identifier",
            "source_element_identifier",
            "from",
            "from_id",
        ]
        keys_dst = [
            "target",
            "target_id",
            "target_identifier",
            "target_element_identifier",
            "to",
            "to_id",
        ]
        srcs = [rel.get(k) for k in keys_src if isinstance(rel.get(k), str)]
        dsts = [rel.get(k) for k in keys_dst if isinstance(rel.get(k), str)]

        pairs: List[Tuple[str, str]] = []
        for s in srcs:
            for t in dsts:
                if s in node_index and t in node_index:
                    pairs.append((s, t))
        # fallback: take any two id-like strings in dict (orderless)
        if not pairs:
            ids = [v for v in rel.values() if isinstance(v, str) and v in node_index]
            if len(ids) >= 2:
                pairs.append((ids[0], ids[1]))
        return pairs

    for rel_list in rel_lists:
        for rel in rel_list:
            for pair in extract_pairs(rel):
                edges.add(pair)
    return edges


def build_adjacency(edges: Set[Tuple[str, str]]) -> Dict[str, Set[str]]:
    adj: Dict[str, Set[str]] = {}
    for s, t in edges:
        adj.setdefault(s, set()).add(t)
    return adj


# ─────────────────────────────────────────────────────────────────────────────
# Coverage / traversal: Role → Task → Skill → Knowledge
# ─────────────────────────────────────────────────────────────────────────────


def bfs_to_types(
    start: str,
    adj: Dict[str, Set[str]],
    nodes: Dict[str, Node],
    want_types: Set[str],
    max_depth: int = 4,
) -> Set[str]:
    out: Set[str] = set()
    seen: Set[str] = {start}
    q: List[Tuple[str, int]] = [(start, 0)]
    while q:
        cur, d = q.pop(0)
        if d >= max_depth:
            continue
        for nxt in adj.get(cur, set()):
            if nxt in seen:
                continue
            seen.add(nxt)
            n = nodes.get(nxt)
            if n and n.type in want_types:
                out.add(nxt)
            q.append((nxt, d + 1))
    return out


def role_coverage(
    role_id: str,
    adj: Dict[str, Set[str]],
    nodes: Dict[str, Node],
    depth: int = 5,
) -> Dict[str, Set[str]]:
    return {
        "tasks": bfs_to_types(role_id, adj, nodes, {"task"}, max_depth=depth),
        "skills": bfs_to_types(role_id, adj, nodes, {"skill"}, max_depth=depth),
        "knowledge": bfs_to_types(role_id, adj, nodes, {"knowledge"}, max_depth=depth),
    }


# SOC / GRC focus weights
FOCUS_WEIGHTS = {
    "soc": {"tasks": 1.0, "skills": 0.6, "knowledge": 0.3},
    "grc": {"tasks": 0.4, "skills": 0.8, "knowledge": 1.0},
}


def weighted_score(coverage: Dict[str, Set[str]], focus: str) -> float:
    """Compute the weighted TKS score for a given coverage dict under a focus strategy."""
    w = FOCUS_WEIGHTS[focus]
    return (
        w["tasks"] * len(coverage["tasks"])
        + w["skills"] * len(coverage["skills"])
        + w["knowledge"] * len(coverage["knowledge"])
    )


# ─────────────────────────────────────────────────────────────────────────────
# Gap analysis (Tasks/Skills/Knowledge coverage)
# ─────────────────────────────────────────────────────────────────────────────


def parse_role_ids(path: Path) -> Set[str]:
    ids: Set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if re.match(r"^[A-Z]{2}-WRL-\d{3}$", line):
            ids.add(line)
    return ids


def compute_coverage_union(
    role_set: Set[str], adj: Dict[str, Set[str]], nodes: Dict[str, Node], depth: int = 5
) -> Dict[str, Set[str]]:
    T, S, K = set(), set(), set()
    for r in role_set:
        if r not in nodes:
            continue
        c = role_coverage(r, adj, nodes, depth=depth)
        T |= c["tasks"]
        S |= c["skills"]
        K |= c["knowledge"]
    return {"tasks": T, "skills": S, "knowledge": K}


def export_gap_report(
    outpath: Path,
    nodes: Dict[str, Node],
    adj: Dict[str, Set[str]],
    current: Set[str],
    target: Set[str],
    depth: int = 5,
    focus: str = "soc",
) -> None:
    cur = compute_coverage_union(current, adj, nodes, depth)
    tgt = compute_coverage_union(target, adj, nodes, depth)

    gapT = tgt["tasks"] - cur["tasks"]
    gapS = tgt["skills"] - cur["skills"]
    gapK = tgt["knowledge"] - cur["knowledge"]

    w = FOCUS_WEIGHTS[focus]
    cur_score = weighted_score(cur, focus)
    tgt_score = weighted_score(tgt, focus)

    def rtitle(rid: str) -> str:
        return nodes[rid].title if rid in nodes else rid

    lines = []
    lines.append("# NICE Workforce Gap Analysis")
    lines.append(
        f"_Focus: **{focus.upper()}** · Weights T={w['tasks']} S={w['skills']} K={w['knowledge']}_"
    )
    lines.append("")
    lines.append("## Role Delta")
    add_roles = sorted(target - current)
    rem_roles = sorted(current - target)
    lines.append(
        "**Add (Target \\ Current):** "
        + (", ".join(f"{rtitle(r)} ({r})" for r in add_roles) or "(none)")
    )
    lines.append(
        "**Remove (Current \\ Target):** "
        + (", ".join(f"{rtitle(r)} ({r})" for r in rem_roles) or "(none)")
    )
    lines.append("")
    lines.append("## Weighted Coverage Scores")
    lines.append(f"| Metric | Current | Target | Gap |")
    lines.append(f"|--------|---------|--------|-----|")
    lines.append(
        f"| Tasks | {len(cur['tasks'])} | {len(tgt['tasks'])} | **+{len(gapT)}** |"
    )
    lines.append(
        f"| Skills | {len(cur['skills'])} | {len(tgt['skills'])} | **+{len(gapS)}** |"
    )
    lines.append(
        f"| Knowledge | {len(cur['knowledge'])} | {len(tgt['knowledge'])} | **+{len(gapK)}** |"
    )
    lines.append(
        f"| **Weighted Score** | {cur_score:.1f} | {tgt_score:.1f} | **+{tgt_score - cur_score:.1f}** |"
    )
    lines.append("")
    lines.append("## Top Missing Tasks (first 20)")
    for tid in list(sorted(gapT))[:20]:
        n = nodes.get(tid)
        lines.append(f"- **{tid}**: {(n.text or n.title) if n else ''}")
    lines.append("")
    lines.append("## Top Missing Skills (first 10)")
    for sid in list(sorted(gapS))[:10]:
        n = nodes.get(sid)
        lines.append(f"- **{sid}**: {(n.text or n.title) if n else ''}")
    lines.append("")
    lines.append("## Top Missing Knowledge (first 10)")
    for kid in list(sorted(gapK))[:10]:
        n = nodes.get(kid)
        lines.append(f"- **{kid}**: {(n.text or n.title) if n else ''}")

    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(lines), encoding="utf-8")
    print(f"  Gap report → {outpath}")


# ─────────────────────────────────────────────────────────────────────────────
# Multi-objective optimization (greedy set cover + weighted score + budget)
# ─────────────────────────────────────────────────────────────────────────────


def load_role_costs(csv_path: Path) -> Dict[str, RoleCost]:
    costs: Dict[str, RoleCost] = {}
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rc = RoleCost(
                role_id=row["role_id"].strip(),
                title=row.get("title", "").strip(),
                category=row.get("category", "").strip(),
                hire_cost=float(row.get("hire_cost", 0)),
                training_cost=float(row.get("training_cost", 0)),
                outsource_cost=float(row.get("outsource_cost", 0)),
                time_to_hire_months=int(row.get("time_to_hire_months", 3)),
                cert_bonus_cost=float(row.get("cert_bonus_cost", 0)),
                criticality_score=float(row.get("criticality_score", 5)),
                risk_impact_pct=float(row.get("risk_impact_pct", 0)),
                action=row.get("action", "hire").strip(),
            )
            costs[rc.role_id] = rc
    return costs


def action_cost_2yr(rc: RoleCost) -> float:
    """Compute realistic 2-year total cost for a role given its action type."""
    if rc.action == "train":
        return rc.training_cost + rc.cert_bonus_cost
    elif rc.action == "outsource":
        return rc.outsource_cost * 2  # 2 years
    else:  # hire
        return rc.hire_cost * 2 + rc.cert_bonus_cost


def recommend(
    nodes: Dict[str, Node],
    adj: Dict[str, Set[str]],
    focus: str,
    top_n: int = 8,
    depth: int = 5,
    budget: float = 250_000,
    costs_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    focus = focus.lower()
    w = FOCUS_WEIGHTS[focus]

    all_roles = [
        nid
        for nid, n in nodes.items()
        if n.type == "work_role" and re.match(r"^[A-Z]{2}-WRL-\d{3}$", nid)
    ]

    # Load cost data if available
    role_costs: Dict[str, RoleCost] = {}
    if costs_path and costs_path.exists():
        role_costs = load_role_costs(costs_path)

    # Pre-compute coverage for all candidate roles
    role_cov: Dict[str, Dict[str, Set[str]]] = {}
    for r in all_roles:
        role_cov[r] = role_coverage(r, adj, nodes, depth=depth)

    chosen: List[Dict[str, Any]] = []
    covered: Dict[str, Set[str]] = {"tasks": set(), "skills": set(), "knowledge": set()}
    remaining_budget = budget

    for _ in range(top_n):
        best = None
        best_score = -1.0
        best_cost = 0.0

        for r in all_roles:
            if any(c["role_id"] == r for c in chosen):
                continue

            marginal = {
                "tasks": role_cov[r]["tasks"] - covered["tasks"],
                "skills": role_cov[r]["skills"] - covered["skills"],
                "knowledge": role_cov[r]["knowledge"] - covered["knowledge"],
            }

            gain = (
                w["tasks"] * len(marginal["tasks"])
                + w["skills"] * len(marginal["skills"])
                + w["knowledge"] * len(marginal["knowledge"])
            )
            if gain == 0:
                continue

            # Cost-adjusted gain
            rc = role_costs.get(r)
            cost = action_cost_2yr(rc) if rc else 80_000  # default estimate
            if cost > remaining_budget:
                continue

            # Criticality bonus
            crit = rc.criticality_score if rc else 5.0
            adjusted = gain * (1 + 0.05 * crit) / (cost / 50_000 + 1)

            if adjusted > best_score:
                best_score = adjusted
                best = r
                best_cost = cost

        if not best:
            break

        rc = role_costs.get(best)
        chosen.append(
            {
                "role_id": best,
                "title": nodes[best].title,
                "action": rc.action if rc else "hire",
                "cost_2yr": best_cost,
                "criticality": rc.criticality_score if rc else 5.0,
                "risk_impact_pct": rc.risk_impact_pct if rc else 0,
                "new_tasks": len(role_cov[best]["tasks"] - covered["tasks"]),
                "new_skills": len(role_cov[best]["skills"] - covered["skills"]),
                "new_knowledge": len(
                    role_cov[best]["knowledge"] - covered["knowledge"]
                ),
                "weighted_gain": round(best_score, 2),
            }
        )
        covered["tasks"] |= role_cov[best]["tasks"]
        covered["skills"] |= role_cov[best]["skills"]
        covered["knowledge"] |= role_cov[best]["knowledge"]
        remaining_budget -= best_cost

    return chosen


def export_reco_md(
    outpath: Path,
    nodes: Dict[str, Node],
    picks: List[Dict[str, Any]],
    adj: Dict[str, Set[str]],
    focus: str,
    budget: float = 250_000,
    depth: int = 5,
) -> None:
    total_cost = sum(p["cost_2yr"] for p in picks)

    # Accumulate total TKS coverage across all picked roles
    total_cov: Dict[str, Set[str]] = {
        "tasks": set(),
        "skills": set(),
        "knowledge": set(),
    }
    for p in picks:
        cov = role_coverage(p["role_id"], adj, nodes, depth=depth)
        total_cov["tasks"] |= cov["tasks"]
        total_cov["skills"] |= cov["skills"]
        total_cov["knowledge"] |= cov["knowledge"]

    score = weighted_score(total_cov, focus)

    lines = [
        f"# CISO Team Recommendation — {focus.upper()} Focus",
        f"_Budget: ${budget:,.0f} · 2-Year Horizon_",
        "",
        f"| # | Role | ID | Action | 2yr Cost | New Tasks | Weighted Gain |",
        f"|---|------|----|--------|----------|-----------|---------------|",
    ]
    for i, p in enumerate(picks, 1):
        lines.append(
            f"| {i} | {p['title']} | {p['role_id']} | {p['action'].upper()} "
            f"| ${p['cost_2yr']:,.0f} | +{p['new_tasks']} | {p['weighted_gain']:.1f} |"
        )

    lines += [
        "",
        f"**Total 2-Year Cost:** ${total_cost:,.0f} / ${budget:,.0f}",
        f"**Budget Remaining:** ${budget - total_cost:,.0f}",
        "",
        f"**Coverage Summary:**",
        f"- Tasks: {len(total_cov['tasks'])} | Skills: {len(total_cov['skills'])} | Knowledge: {len(total_cov['knowledge'])}",
        f"- **Weighted Score ({focus.upper()}):** {score:.1f}",
    ]

    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(lines), encoding="utf-8")
    print(f"  Recommendation → {outpath}")


# ─────────────────────────────────────────────────────────────────────────────
# Risk scenario simulation
# ─────────────────────────────────────────────────────────────────────────────


def load_risk_scenarios(json_path: Path) -> List[Dict[str, Any]]:
    return json.loads(json_path.read_text(encoding="utf-8"))


def simulate_risk(
    outpath: Path,
    nodes: Dict[str, Node],
    adj: Dict[str, Set[str]],
    current_roles: Set[str],
    plan_roles: Set[str],
    scenarios: List[Dict[str, Any]],
    depth: int = 5,
) -> None:
    cur_tasks = compute_coverage_union(current_roles, adj, nodes, depth)["tasks"]
    plan_tasks = compute_coverage_union(current_roles | plan_roles, adj, nodes, depth)[
        "tasks"
    ]

    lines = [
        "# Risk Scenario Mitigation Report",
        "",
        "| Scenario | Required Tasks | Before (Current) | After (Plan) | Risk Reduction |",
        "|----------|---------------|-----------------|--------------|----------------|",
    ]

    for s in scenarios:
        name = s["name"]
        required: List[str] = s.get("required_tasks", [])
        if not required:
            continue
        total = len(required)
        before = sum(1 for t in required if t in cur_tasks)
        after = sum(1 for t in required if t in plan_tasks)
        before_pct = before / total * 100 if total else 0
        after_pct = after / total * 100 if total else 0
        lines.append(
            f"| {name} | {total} | {before}/{total} ({before_pct:.0f}%) "
            f"| {after}/{total} ({after_pct:.0f}%) | +{after_pct - before_pct:.0f}% |"
        )

    lines.append("")
    lines.append("## Narrative")
    for s in scenarios:
        name = s["name"]
        required = s.get("required_tasks", [])
        if not required:
            continue
        total = len(required)
        after = sum(1 for t in required if t in plan_tasks)
        lines.append(
            f"**{name}**: By executing the proposed hiring and training plan, the organization mitigates "
            f"{after}/{total} ({after/total*100:.0f}%) of critical tasks in this scenario. "
            f"{s.get('description', '')}"
        )
        lines.append("")

    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(lines), encoding="utf-8")
    print(f"  Risk report → {outpath}")


# ─────────────────────────────────────────────────────────────────────────────
# 2-year CISO workforce plan
# ─────────────────────────────────────────────────────────────────────────────


def export_plan(
    outpath: Path,
    nodes: Dict[str, Node],
    adj: Dict[str, Set[str]],
    current: Set[str],
    picks: List[Dict[str, Any]],
    focus: str,
    budget: float = 250_000,
    depth: int = 5,
) -> None:
    trains = [p for p in picks if p["action"] == "train"]
    hires = [p for p in picks if p["action"] == "hire"]
    outsources = [p for p in picks if p["action"] == "outsource"]

    total_cost = sum(p["cost_2yr"] for p in picks)

    lines = [
        "# 2-Year CISO Workforce Optimization Plan",
        f"_Organization Focus: {focus.upper()} · Total Budget: ${budget:,.0f}_",
        "",
        "## Executive Summary",
        "This plan transitions the organization from a reactive, alert-heavy posture to a **proactive, "
        "security-by-design** operation over 24 months. The strategy combines targeted upskilling of "
        "existing staff, strategic new hires, and selective outsourcing of specialized capabilities.",
        "",
        "## Baseline (Current Workforce)",
        ", ".join(f"`{r}` {nodes[r].title}" for r in sorted(current) if r in nodes)
        or "(none)",
        "",
        "## Phased Action Plan",
        "",
        "### Phase 1 — Quick Wins (Months 1-6): Training & Upskilling",
    ]
    if trains:
        for p in trains:
            lines.append(
                f"- **TRAIN**: {p['title']} ({p['role_id']}) — ${p['cost_2yr']:,.0f}"
            )
            lines.append(
                f"  _Rationale_: Upskill existing staff to cover {p['new_tasks']} new tasks immediately."
            )
    else:
        lines.append("_(No training actions in this plan)_")

    lines += [
        "",
        "### Phase 2 — Strategic Hires (Months 3-18): New Headcount",
    ]
    if hires:
        for p in hires:
            lines.append(
                f"- **HIRE**: {p['title']} ({p['role_id']}) — ${p['cost_2yr']:,.0f} / 2yr"
            )
            lines.append(
                f"  _Adds_: {p['new_tasks']} tasks · {p['new_skills']} skills · {p['new_knowledge']} knowledge items"
            )
    else:
        lines.append("_(No hiring actions in this plan)_")

    lines += [
        "",
        "### Phase 3 — Outsourcing (Months 1-24): Specialized External Services",
    ]
    if outsources:
        for p in outsources:
            lines.append(
                f"- **OUTSOURCE**: {p['title']} ({p['role_id']}) — ${p['cost_2yr']:,.0f} / 2yr"
            )
    else:
        lines.append("_(No outsourcing actions in this plan)_")

    lines += [
        "",
        "## Budget Summary",
        f"| Category | Count | 2-Year Cost |",
        f"|----------|-------|-------------|",
        f"| Training | {len(trains)} | ${sum(p['cost_2yr'] for p in trains):,.0f} |",
        f"| Hiring | {len(hires)} | ${sum(p['cost_2yr'] for p in hires):,.0f} |",
        f"| Outsourcing | {len(outsources)} | ${sum(p['cost_2yr'] for p in outsources):,.0f} |",
        f"| **TOTAL** | **{len(picks)}** | **${total_cost:,.0f}** |",
        f"| Remaining | | **${budget - total_cost:,.0f}** |",
        "",
        "## Expected Outcomes (After 24 Months)",
        f"- Transition from reactive to proactive security posture",
        f"- {sum(p['new_tasks'] for p in picks)} net-new NICE tasks covered",
        f"- Ransomware, Data Leaks, and Audit Failure risk significantly reduced (see risk report)",
    ]

    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(lines), encoding="utf-8")
    print(f"  2-Year plan → {outpath}")


# ─────────────────────────────────────────────────────────────────────────────
# Interactive HTML Dashboard
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CISO DSS Dashboard — NICE Framework</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root{--bg:#0f1117;--surface:#1a1d2e;--border:#2d3148;--accent:#6c63ff;--accent2:#00d4ff;--green:#00e676;--red:#ff5252;--yellow:#ffd740;--text:#e8eaf6;--muted:#8892b0;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;}
  header{background:linear-gradient(135deg,#1a1d2e 0%,#252841 100%);border-bottom:1px solid var(--border);padding:1.5rem 2rem;display:flex;align-items:center;gap:1rem;}
  header h1{font-size:1.4rem;font-weight:700;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
  header span{background:var(--accent);color:#fff;font-size:.7rem;padding:.2rem .6rem;border-radius:999px;font-weight:600;}
  .main{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 70px);}
  nav{background:var(--surface);border-right:1px solid var(--border);padding:1.5rem 0;}
  nav a{display:block;padding:.7rem 1.5rem;color:var(--muted);text-decoration:none;font-size:.9rem;border-left:3px solid transparent;transition:all .2s;}
  nav a:hover,nav a.active{color:var(--text);border-left-color:var(--accent);background:rgba(108,99,255,.1);}
  .content{padding:2rem;overflow-y:auto;}
  .page{display:none;}.page.active{display:block;}
  h2{font-size:1.2rem;font-weight:700;margin-bottom:1.5rem;color:var(--accent2);}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem;}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.2rem;position:relative;overflow:hidden;}
  .card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:var(--accent);}
  .card.green::before{background:var(--green);}
  .card.red::before{background:var(--red);}
  .card.yellow::before{background:var(--yellow);}
  .card-label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.4rem;}
  .card-value{font-size:2rem;font-weight:700;color:var(--text);}
  .card-sub{font-size:.8rem;color:var(--muted);margin-top:.3rem;}
  .chart-container{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:2rem;}
  .chart-container h3{font-size:.95rem;font-weight:600;margin-bottom:1rem;color:var(--muted);}
  canvas{max-height:300px;}
  table{width:100%;border-collapse:collapse;background:var(--surface);border-radius:12px;overflow:hidden;border:1px solid var(--border);}
  th{background:rgba(108,99,255,.2);color:var(--muted);font-size:.78rem;text-transform:uppercase;padding:.8rem 1rem;text-align:left;}
  td{padding:.75rem 1rem;font-size:.88rem;border-top:1px solid var(--border);}
  tr:hover td{background:rgba(255,255,255,.02);}
  .badge{display:inline-block;padding:.15rem .6rem;border-radius:999px;font-size:.72rem;font-weight:600;}
  .badge-hire{background:rgba(108,99,255,.2);color:var(--accent);}
  .badge-train{background:rgba(0,230,118,.2);color:var(--green);}
  .badge-outsource{background:rgba(255,215,64,.2);color:var(--yellow);}
  .risk-bar{height:10px;border-radius:5px;background:var(--border);overflow:hidden;margin-top:.3rem;}
  .risk-fill{height:100%;border-radius:5px;background:linear-gradient(90deg,var(--red),var(--yellow),var(--green));transition:width .6s ease;}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;}
  .tag{background:rgba(0,212,255,.1);color:var(--accent2);font-size:.72rem;padding:.15rem .5rem;border-radius:4px;display:inline-block;margin:.1rem;}
  select,input{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:.5rem .8rem;border-radius:8px;font-size:.88rem;}
  .btn{background:var(--accent);color:#fff;border:none;padding:.6rem 1.4rem;border-radius:8px;cursor:pointer;font-size:.88rem;font-weight:600;transition:opacity .2s;}
  .btn:hover{opacity:.85;}
  .timeline{position:relative;padding-left:2rem;}
  .timeline::before{content:'';position:absolute;left:.5rem;top:0;bottom:0;width:2px;background:var(--border);}
  .tl-item{position:relative;margin-bottom:1.5rem;}
  .tl-dot{position:absolute;left:-1.75rem;top:.25rem;width:12px;height:12px;border-radius:50%;background:var(--accent);}
  .tl-item.green .tl-dot{background:var(--green);}
  .tl-item.yellow .tl-dot{background:var(--yellow);}
  .tl-item.red .tl-dot{background:var(--red);}
  .tl-title{font-weight:600;font-size:.9rem;}
  .tl-sub{color:var(--muted);font-size:.82rem;margin-top:.2rem;}
  .progress-row{display:flex;align-items:center;gap:1rem;margin-bottom:.8rem;}
  .progress-label{min-width:140px;font-size:.85rem;color:var(--muted);}
  .progress-bar{flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden;}
  .progress-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--accent),var(--accent2));}
  .progress-val{min-width:50px;text-align:right;font-size:.85rem;font-weight:600;}
</style>
</head>
<body>
<header>
  <h1>🛡️ CISO Decision Support System</h1>
  <span>NICE Framework v2.0</span>
  <span style="margin-left:auto;background:var(--green);">Dashboard v1.0</span>
</header>
<div class="main">
  <nav>
    <a class="active" onclick="show('overview',this)">📊 Overview</a>
    <a onclick="show('gap',this)">🔍 Gap Analysis</a>
    <a onclick="show('recommend',this)">🎯 Recommendations</a>
    <a onclick="show('budget',this)">💰 Budget</a>
    <a onclick="show('risk',this)">⚠️ Risk Scenarios</a>
    <a onclick="show('timeline',this)">📅 2-Year Plan</a>
  </nav>
  <div class="content">

    <!-- OVERVIEW -->
    <div id="overview" class="page active">
      <h2>Executive Overview</h2>
      <div class="cards">
        <div class="card"><div class="card-label">Current Roles</div><div class="card-value" id="cur-roles">—</div><div class="card-sub">Baseline workforce</div></div>
        <div class="card green"><div class="card-label">Target Roles</div><div class="card-value" id="tgt-roles">—</div><div class="card-sub">After optimization</div></div>
        <div class="card"><div class="card-label">Total Budget</div><div class="card-value" id="total-budget">—</div><div class="card-sub">2-year horizon</div></div>
        <div class="card yellow"><div class="card-label">Risk Reduction</div><div class="card-value" id="risk-avg">—</div><div class="card-sub">Avg across scenarios</div></div>
      </div>
      <div class="grid2">
        <div class="chart-container">
          <h3>TKS Coverage: Current vs Target</h3>
          <canvas id="coverageChart"></canvas>
        </div>
        <div class="chart-container">
          <h3>Budget Allocation by Action Type</h3>
          <canvas id="budgetPieChart"></canvas>
        </div>
      </div>
      <div class="chart-container">
        <h3>Risk Reduction by Scenario (Before → After Plan)</h3>
        <canvas id="riskChart"></canvas>
      </div>
    </div>

    <!-- GAP -->
    <div id="gap" class="page">
      <h2>Gap Analysis</h2>
      <div class="cards">
        <div class="card red"><div class="card-label">Missing Tasks</div><div class="card-value" id="gap-tasks">—</div></div>
        <div class="card red"><div class="card-label">Missing Skills</div><div class="card-value" id="gap-skills">—</div></div>
        <div class="card red"><div class="card-label">Missing Knowledge</div><div class="card-value" id="gap-knowledge">—</div></div>
        <div class="card"><div class="card-label">Weighted Gap Score</div><div class="card-value" id="gap-score">—</div></div>
      </div>
      <div class="grid2">
        <div class="chart-container">
          <h3 id="soc-gap-title">SOC Focus Gap</h3>
          <div id="soc-bars"></div>
        </div>
        <div class="chart-container">
          <h3 id="grc-gap-title">GRC Focus Gap</h3>
          <div id="grc-bars"></div>
        </div>
      </div>
      <div class="chart-container">
        <h3>Current vs Target Role Mapping</h3>
        <table>
          <thead><tr><th>Role ID</th><th>Title</th><th>Category</th><th>Status</th></tr></thead>
          <tbody id="role-table"></tbody>
        </table>
      </div>
    </div>

    <!-- RECOMMENDATIONS -->
    <div id="recommend" class="page">
      <h2>Team Recommendations</h2>
      <div style="display:flex;gap:1rem;margin-bottom:1.5rem;align-items:center;">
        <select id="focus-sel" onchange="renderReco()">
        <option value="soc">SOC Focus</option>
        <option value="grc">GRC Focus</option>
      </select>
        <span style="color:var(--muted);font-size:.85rem;">Weights auto-adjusted per focus</span>
      </div>
      <table>
        <thead><tr><th>#</th><th>Role</th><th>Action</th><th>New Tasks</th><th>New Skills</th><th>New Knowledge</th><th>Weighted Gain</th><th>2yr Cost</th></tr></thead>
        <tbody id="reco-table"></tbody>
      </table>
      <div class="chart-container" style="margin-top:1.5rem;">
        <h3>Marginal Coverage Gain per Role (selected focus)</h3>
        <canvas id="recoChart"></canvas>
      </div>
    </div>

    <!-- BUDGET -->
    <div id="budget" class="page">
      <h2>Budget Analysis</h2>
      <div class="cards">
        <div class="card"><div class="card-label">Total Allocated</div><div class="card-value" id="b-alloc">—</div></div>
        <div class="card green"><div class="card-label">Remaining</div><div class="card-value" id="b-remain">—</div></div>
        <div class="card"><div class="card-label">Training</div><div class="card-value" id="b-train">—</div></div>
        <div class="card"><div class="card-label">Hiring</div><div class="card-value" id="b-hire">—</div></div>
        <div class="card"><div class="card-label">Outsourcing</div><div class="card-value" id="b-out">—</div></div>
      </div>
      <div class="chart-container">
        <h3>Cost Breakdown per Role (2-Year)</h3>
        <canvas id="costChart"></canvas>
      </div>
      <div class="chart-container">
        <h3>Cost vs Coverage Efficiency</h3>
        <canvas id="effChart"></canvas>
      </div>
    </div>

    <!-- RISK -->
    <div id="risk" class="page">
      <h2>Risk Scenario Simulation</h2>
      <table>
        <thead><tr><th>Scenario</th><th>Required Tasks</th><th>Before Plan</th><th>After Plan</th><th>Improvement</th></tr></thead>
        <tbody id="risk-table"></tbody>
      </table>
      <div class="chart-container" style="margin-top:1.5rem;">
        <h3>Risk Reduction Visual</h3>
        <div id="risk-bars-detail"></div>
      </div>
    </div>

    <!-- TIMELINE -->
    <div id="timeline" class="page">
      <h2>2-Year Implementation Roadmap</h2>
      <div class="grid2">
        <div>
          <div class="chart-container">
            <h3>Phase 1 — Months 1-6: Training</h3>
            <div class="timeline" id="tl-train"></div>
          </div>
          <div class="chart-container">
            <h3>Phase 2 — Months 3-18: Hiring</h3>
            <div class="timeline" id="tl-hire"></div>
          </div>
        </div>
        <div>
          <div class="chart-container">
            <h3>Phase 3 — Months 1-24: Outsourcing</h3>
            <div class="timeline" id="tl-outsource"></div>
          </div>
          <div class="chart-container">
            <h3>Cumulative Coverage Growth</h3>
            <canvas id="growthChart"></canvas>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>

<script>
// ─── Injected data ───
const DATA = __DATA__;

// ─── Navigation ───
function show(id, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  el.classList.add('active');
  renderPage(id);
}

// ─── Helpers ───
function fmt(n) { return '$' + Math.round(n).toLocaleString(); }
function fmtk(n) { return n >= 1000 ? '$' + (n/1000).toFixed(0) + 'k' : '$' + Math.round(n); }
function pct(n) { return Math.round(n) + '%'; }
function badge(a) { return `<span class="badge badge-${a}">${a.toUpperCase()}</span>`; }

// ─── Chart defaults ───
Chart.defaults.color = '#8892b0';
Chart.defaults.borderColor = '#2d3148';
const COLORS = ['#6c63ff','#00d4ff','#00e676','#ffd740','#ff5252','#ff6e40','#40c4ff','#69f0ae'];

let charts = {};
function mkChart(id, config) {
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart(document.getElementById(id), config);
}

// ─── Page renders ───
let recoFocus = 'soc';

function renderPage(id) {
  if (id === 'overview') renderOverview();
  else if (id === 'gap') renderGap();
  else if (id === 'recommend') renderReco();
  else if (id === 'budget') renderBudget();
  else if (id === 'risk') renderRisk();
  else if (id === 'timeline') renderTimeline();
}

function renderOverview() {
  document.getElementById('cur-roles').textContent = DATA.current_roles.length;
  document.getElementById('tgt-roles').textContent = DATA.plan.length + DATA.current_roles.length;
  document.getElementById('total-budget').textContent = fmtk(DATA.budget);
  const avgRisk = DATA.scenarios.reduce((s,sc) => s + sc.after_pct, 0) / (DATA.scenarios.length || 1);
  document.getElementById('risk-avg').textContent = pct(avgRisk);

  // Coverage chart
  const cur = DATA.coverage.current;
  const tgt = DATA.coverage.target;
  mkChart('coverageChart', {
    type: 'bar',
    data: {
      labels: ['Tasks','Skills','Knowledge'],
      datasets: [
        {label:'Current', data:[cur.tasks, cur.skills, cur.knowledge], backgroundColor:'rgba(108,99,255,.6)'},
        {label:'After Plan', data:[tgt.tasks, tgt.skills, tgt.knowledge], backgroundColor:'rgba(0,212,255,.6)'},
      ]
    },
    options: {responsive:true, plugins:{legend:{position:'top'}}, scales:{y:{beginAtZero:true}}}
  });

  // Budget pie
  const train = DATA.plan.filter(p=>p.action==='train').reduce((s,p)=>s+p.cost_2yr,0);
  const hire = DATA.plan.filter(p=>p.action==='hire').reduce((s,p)=>s+p.cost_2yr,0);
  const out = DATA.plan.filter(p=>p.action==='outsource').reduce((s,p)=>s+p.cost_2yr,0);
  mkChart('budgetPieChart', {
    type: 'doughnut',
    data: {
      labels: ['Training','Hiring','Outsourcing'],
      datasets: [{data:[train,hire,out], backgroundColor:['#00e676','#6c63ff','#ffd740']}]
    },
    options: {responsive:true, plugins:{legend:{position:'right'}}}
  });

  // Risk bar chart
  mkChart('riskChart', {
    type: 'bar',
    data: {
      labels: DATA.scenarios.map(s=>s.name),
      datasets: [
        {label:'Before Plan', data:DATA.scenarios.map(s=>s.before_pct), backgroundColor:'rgba(255,82,82,.6)'},
        {label:'After Plan', data:DATA.scenarios.map(s=>s.after_pct), backgroundColor:'rgba(0,230,118,.6)'},
      ]
    },
    options: {responsive:true, plugins:{legend:{position:'top'}}, scales:{y:{max:100,beginAtZero:true}}}
  });
}

function renderGap() {
  const gap = DATA.gap;
  document.getElementById('gap-tasks').textContent = gap.missing_tasks;
  document.getElementById('gap-skills').textContent = gap.missing_skills;
  document.getElementById('gap-knowledge').textContent = gap.missing_knowledge;
  const activeGap = DATA.focus === 'grc' ? gap.weighted_gap_grc : gap.weighted_gap_soc;
  document.getElementById('gap-score').textContent = activeGap.toFixed(1) + ' (' + DATA.focus.toUpperCase() + ')';

  // Update gap titles with actual weights from DATA
  const sw = DATA.focus_weights.soc;
  const gw = DATA.focus_weights.grc;
  document.getElementById('soc-gap-title').textContent = `SOC Focus Gap (T=${sw.tasks} S=${sw.skills} K=${sw.knowledge})`;
  document.getElementById('grc-gap-title').textContent = `GRC Focus Gap (T=${gw.tasks} S=${gw.skills} K=${gw.knowledge})`;

  // SOC bars
  const socBars = [
    {label:'Tasks',cur:DATA.coverage.current.tasks,tgt:DATA.coverage.target.tasks},
    {label:'Skills',cur:DATA.coverage.current.skills,tgt:DATA.coverage.target.skills},
    {label:'Knowledge',cur:DATA.coverage.current.knowledge,tgt:DATA.coverage.target.knowledge},
  ];
  document.getElementById('soc-bars').innerHTML = socBars.map(b => `
    <div class="progress-row">
      <span class="progress-label">${b.label}</span>
      <div class="progress-bar"><div class="progress-fill" style="width:${b.cur/b.tgt*100}%"></div></div>
      <span class="progress-val">${b.cur}/${b.tgt}</span>
    </div>`).join('');
  document.getElementById('grc-bars').innerHTML = socBars.map(b => `
    <div class="progress-row">
      <span class="progress-label">${b.label}</span>
      <div class="progress-bar"><div class="progress-fill" style="width:${b.cur/b.tgt*100}%;background:linear-gradient(90deg,#ffd740,#00d4ff)"></div></div>
      <span class="progress-val">${b.cur}/${b.tgt}</span>
    </div>`).join('');

  // Role table
  const allRoles = [...new Set([...DATA.current_roles, ...DATA.target_roles])];
  document.getElementById('role-table').innerHTML = allRoles.map(r => {
    const isCur = DATA.current_roles.includes(r);
    const isTgt = DATA.target_roles.includes(r);
    const status = isCur && isTgt ? '<span class="badge badge-train">KEEP</span>' :
                   isCur ? '<span class="badge" style="background:rgba(255,82,82,.2);color:#ff5252">REMOVE</span>' :
                   '<span class="badge badge-hire">ADD</span>';
    const info = DATA.role_info[r] || {};
    return `<tr><td><code>${r}</code></td><td>${info.title||r}</td><td>${r.split('-')[0]}</td><td>${status}</td></tr>`;
  }).join('');
}

function renderReco() {
  recoFocus = document.getElementById('focus-sel').value;
  const picks = DATA.plan;
  document.getElementById('reco-table').innerHTML = picks.map((p,i) => `
    <tr>
      <td>${i+1}</td>
      <td><strong>${p.title}</strong><br><code style="font-size:.75rem;color:var(--muted)">${p.role_id}</code></td>
      <td>${badge(p.action)}</td>
      <td>+${p.new_tasks}</td>
      <td>+${p.new_skills}</td>
      <td>+${p.new_knowledge}</td>
      <td>${p.weighted_gain_soc.toFixed(1)} SOC / ${p.weighted_gain_grc.toFixed(1)} GRC</td>
      <td>${fmt(p.cost_2yr)}</td>
    </tr>`).join('');

  mkChart('recoChart', {
    type: 'bar',
    data: {
      labels: picks.map(p=>p.role_id),
      datasets: [
        {label:'New Tasks', data:picks.map(p=>p.new_tasks), backgroundColor:'rgba(108,99,255,.7)'},
        {label:'New Skills', data:picks.map(p=>p.new_skills), backgroundColor:'rgba(0,212,255,.7)'},
        {label:'New Knowledge', data:picks.map(p=>p.new_knowledge), backgroundColor:'rgba(0,230,118,.7)'},
      ]
    },
    options: {responsive:true, plugins:{legend:{position:'top'}}, scales:{x:{stacked:true},y:{stacked:true,beginAtZero:true}}}
  });
}

function renderBudget() {
  const total = DATA.plan.reduce((s,p)=>s+p.cost_2yr,0);
  const train = DATA.plan.filter(p=>p.action==='train').reduce((s,p)=>s+p.cost_2yr,0);
  const hire = DATA.plan.filter(p=>p.action==='hire').reduce((s,p)=>s+p.cost_2yr,0);
  const out = DATA.plan.filter(p=>p.action==='outsource').reduce((s,p)=>s+p.cost_2yr,0);
  document.getElementById('b-alloc').textContent = fmt(total);
  document.getElementById('b-remain').textContent = fmt(DATA.budget - total);
  document.getElementById('b-train').textContent = fmt(train);
  document.getElementById('b-hire').textContent = fmt(hire);
  document.getElementById('b-out').textContent = fmt(out);

  mkChart('costChart', {
    type: 'bar',
    data: {
      labels: DATA.plan.map(p=>p.role_id),
      datasets: [{label:'2-Year Cost',data:DATA.plan.map(p=>p.cost_2yr), backgroundColor:DATA.plan.map(p=>p.action==='train'?'#00e676':p.action==='outsource'?'#ffd740':'#6c63ff')}]
    },
    options: {responsive:true, plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}}}
  });

  mkChart('effChart', {
    type: 'scatter',
    data: {
      datasets: [{
        label:'Roles',
        data: DATA.plan.map(p=>({x:p.cost_2yr, y:p.new_tasks, label:p.role_id})),
        backgroundColor: COLORS,
        pointRadius: 10,
      }]
    },
    options: {
      responsive: true,
      plugins: {
        tooltip: {callbacks:{label: ctx => `${ctx.raw.label}: ${ctx.raw.y} tasks @ ${fmt(ctx.raw.x)}`}},
        legend:{display:false}
      },
      scales: {x:{title:{display:true,text:'2-Year Cost ($)'}}, y:{title:{display:true,text:'New Tasks Covered'},beginAtZero:true}}
    }
  });
}

function renderRisk() {
  document.getElementById('risk-table').innerHTML = DATA.scenarios.map(s => `
    <tr>
      <td><strong>${s.name}</strong></td>
      <td>${s.total}</td>
      <td>${s.before}/${s.total} (${pct(s.before_pct)})</td>
      <td>${s.after}/${s.total} (${pct(s.after_pct)})</td>
      <td style="color:var(--green)">+${pct(s.after_pct - s.before_pct)}</td>
    </tr>`).join('');

  document.getElementById('risk-bars-detail').innerHTML = DATA.scenarios.map(s => `
    <div style="margin-bottom:1.2rem">
      <div style="display:flex;justify-content:space-between;margin-bottom:.3rem">
        <strong>${s.name}</strong>
        <span style="color:var(--green)">+${pct(s.after_pct - s.before_pct)}</span>
      </div>
      <div style="font-size:.8rem;color:var(--muted);margin-bottom:.3rem">Before: ${pct(s.before_pct)}</div>
      <div class="risk-bar"><div class="risk-fill" style="width:${s.before_pct}%"></div></div>
      <div style="font-size:.8rem;color:var(--green);margin:.3rem 0">After: ${pct(s.after_pct)}</div>
      <div class="risk-bar"><div class="risk-fill" style="width:${s.after_pct}%"></div></div>
    </div>`).join('');
}

function renderTimeline() {
  const trains = DATA.plan.filter(p=>p.action==='train');
  const hires = DATA.plan.filter(p=>p.action==='hire');
  const outsources = DATA.plan.filter(p=>p.action==='outsource');

  function tlItems(arr, cls) {
    if (!arr.length) return '<p style="color:var(--muted);font-size:.85rem">No actions in this phase.</p>';
    return arr.map(p => `
      <div class="tl-item ${cls}">
        <div class="tl-dot"></div>
        <div class="tl-title">${p.title} (${p.role_id})</div>
        <div class="tl-sub">Cost: ${fmt(p.cost_2yr)} · +${p.new_tasks} tasks · +${p.new_skills} skills</div>
      </div>`).join('');
  }

  document.getElementById('tl-train').innerHTML = tlItems(trains, 'green');
  document.getElementById('tl-hire').innerHTML = tlItems(hires, '');
  document.getElementById('tl-outsource').innerHTML = tlItems(outsources, 'yellow');

  // Cumulative growth chart
  let cumT=DATA.coverage.current.tasks, cumS=DATA.coverage.current.skills, cumK=DATA.coverage.current.knowledge;
  const labels=['Month 0'];
  const dT=[cumT], dS=[cumS], dK=[cumK];
  DATA.plan.forEach((p,i) => {
    cumT += p.new_tasks; cumS += p.new_skills; cumK += p.new_knowledge;
    labels.push(`+Role ${i+1}`); dT.push(cumT); dS.push(cumS); dK.push(cumK);
  });
  mkChart('growthChart', {
    type:'line',
    data:{labels, datasets:[
      {label:'Tasks',data:dT,borderColor:'#6c63ff',fill:false},
      {label:'Skills',data:dS,borderColor:'#00d4ff',fill:false},
      {label:'Knowledge',data:dK,borderColor:'#00e676',fill:false},
    ]},
    options:{responsive:true,plugins:{legend:{position:'top'}},scales:{y:{beginAtZero:false}}}
  });
}

// ─── Init ───
document.getElementById('focus-sel').value = DATA.focus;
renderOverview();
</script>
</body>
</html>
"""


def export_dashboard(
    outpath: Path,
    nodes: Dict[str, Node],
    adj: Dict[str, Set[str]],
    current: Set[str],
    picks: List[Dict[str, Any]],
    scenarios: List[Dict[str, Any]],
    focus: str,
    budget: float = 250_000,
    depth: int = 5,
) -> None:
    cur_cov = compute_coverage_union(current, adj, nodes, depth)
    target_roles = current | {p["role_id"] for p in picks}
    tgt_cov = compute_coverage_union(target_roles, adj, nodes, depth)
    cur_tasks = cur_cov["tasks"]
    plan_tasks = tgt_cov["tasks"]

    # Enrich picks with weighted gain scores for both foci (used by dashboard JS)
    for p in picks:
        p["weighted_gain_soc"] = (
            FOCUS_WEIGHTS["soc"]["tasks"] * p["new_tasks"]
            + FOCUS_WEIGHTS["soc"]["skills"] * p["new_skills"]
            + FOCUS_WEIGHTS["soc"]["knowledge"] * p["new_knowledge"]
        )
        p["weighted_gain_grc"] = (
            FOCUS_WEIGHTS["grc"]["tasks"] * p["new_tasks"]
            + FOCUS_WEIGHTS["grc"]["skills"] * p["new_skills"]
            + FOCUS_WEIGHTS["grc"]["knowledge"] * p["new_knowledge"]
        )

    # Scenario data
    scen_data = []
    for s in scenarios:
        req = s.get("required_tasks", [])
        total = len(req)
        before = sum(1 for t in req if t in cur_tasks)
        after = sum(1 for t in req if t in plan_tasks)
        scen_data.append(
            {
                "name": s["name"],
                "total": total,
                "before": before,
                "after": after,
                "before_pct": round(before / total * 100, 1) if total else 0,
                "after_pct": round(after / total * 100, 1) if total else 0,
            }
        )

    role_info = {
        r: {"title": nodes[r].title} for r in nodes if nodes[r].type == "work_role"
    }

    data = {
        "current_roles": list(sorted(current)),
        "target_roles": list(sorted(target_roles)),
        "coverage": {
            "current": {
                "tasks": len(cur_cov["tasks"]),
                "skills": len(cur_cov["skills"]),
                "knowledge": len(cur_cov["knowledge"]),
            },
            "target": {
                "tasks": len(tgt_cov["tasks"]),
                "skills": len(tgt_cov["skills"]),
                "knowledge": len(tgt_cov["knowledge"]),
            },
        },
        "gap": {
            "missing_tasks": len(tgt_cov["tasks"] - cur_cov["tasks"]),
            "missing_skills": len(tgt_cov["skills"] - cur_cov["skills"]),
            "missing_knowledge": len(tgt_cov["knowledge"] - cur_cov["knowledge"]),
            "weighted_gap_soc": weighted_score(tgt_cov, "soc")
            - weighted_score(cur_cov, "soc"),
            "weighted_gap_grc": weighted_score(tgt_cov, "grc")
            - weighted_score(cur_cov, "grc"),
        },
        "plan": picks,
        "scenarios": scen_data,
        "role_info": role_info,
        "focus": focus,
        "budget": budget,
        "focus_weights": FOCUS_WEIGHTS,
    }

    html = DASHBOARD_HTML.replace("__DATA__", json.dumps(data, indent=2))
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(html, encoding="utf-8")
    print(f"  Dashboard → {outpath}")


# ─────────────────────────────────────────────────────────────────────────────
# Sample data generators (for first-run bootstrap)
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_COSTS_CSV = """role_id,title,category,hire_cost,training_cost,outsource_cost,time_to_hire_months,cert_bonus_cost,criticality_score,risk_impact_pct,action
PD-WRL-001,Defensive Cybersecurity,PD,85000,12000,60000,2,3000,8.0,15,train
PD-WRL-003,Incident Response,PD,90000,15000,70000,3,5000,9.0,20,hire
PD-WRL-006,Threat Intelligence,PD,110000,20000,90000,4,8000,8.5,18,outsource
DD-WRL-001,Cybersecurity Architect,DD,130000,25000,100000,5,10000,9.5,25,hire
DD-WRL-003,Software Developer,DD,105000,18000,80000,3,6000,7.0,10,hire
OG-WRL-001,Authorizing Official,OG,120000,10000,85000,4,5000,8.0,12,hire
OG-WRL-002,Security Control Assessor,OG,95000,12000,70000,3,4000,7.5,15,hire
IO-WRL-005,Systems Administrator,IO,75000,8000,55000,2,2000,6.5,8,train
IN-WRL-004,Cyber Defense Analyst,IN,88000,14000,65000,3,4500,8.5,18,hire
PD-WRL-007,Vulnerability Assessment,PD,92000,16000,72000,3,5500,8.0,16,hire
"""

SAMPLE_SCENARIOS_JSON = """[
  {
    "name": "Ransomware Attack",
    "description": "Attacker deploys ransomware across endpoints, encrypting business-critical data.",
    "required_tasks": ["T0161","T0163","T0164","T0175","T0260","T0291","T0309","T0395","T0431","T0503","T0526","T0569","T0175","T0187","T0200","T0214"]
  },
  {
    "name": "Data Leak / Insider Threat",
    "description": "Sensitive PII or IP is exfiltrated by a malicious or negligent insider.",
    "required_tasks": ["T0020","T0023","T0043","T0074","T0099","T0110","T0114","T0120","T0166","T0174","T0190","T0209"]
  },
  {
    "name": "Audit Failure / Compliance Gap",
    "description": "Organization fails regulatory audit (ISO 27001 / NIST / GDPR) due to policy or control gaps.",
    "required_tasks": ["T0027","T0065","T0089","T0092","T0094","T0095","T0264","T0265","T0308","T0339","T0354","T0355"]
  },
  {
    "name": "Supply Chain Compromise",
    "description": "Third-party software or vendor is compromised, leading to lateral movement inside org.",
    "required_tasks": ["T0148","T0187","T0191","T0228","T0268","T0338","T0397","T0414","T0427","T0440"]
  }
]
"""

SAMPLE_CURRENT_ROLES = """PD-WRL-001
PD-WRL-003
IO-WRL-005
"""

SAMPLE_TARGET_ROLES = """PD-WRL-001
PD-WRL-003
PD-WRL-006
PD-WRL-007
DD-WRL-001
DD-WRL-003
OG-WRL-001
OG-WRL-002
IN-WRL-004
IO-WRL-005
"""


def bootstrap_sample_data(outdir: Path) -> None:
    """Write sample CSV, JSON and role list files if they don't exist."""
    files = {
        "roles_costs.csv": SAMPLE_COSTS_CSV,
        "risk_scenarios.json": SAMPLE_SCENARIOS_JSON,
        "current_roles.txt": SAMPLE_CURRENT_ROLES,
        "target_roles.txt": SAMPLE_TARGET_ROLES,
    }
    outdir.mkdir(parents=True, exist_ok=True)
    for fname, content in files.items():
        p = outdir / fname
        if not p.exists():
            p.write_text(content, encoding="utf-8")
            print(f"  Created sample: {p}")
        else:
            print(f"  Exists (skip): {p}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(
        description="CISO DSS — NICE Framework Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Bootstrap sample data files
  python nice_toolkit.py --outdir out init

  # 2. Export NICE graph edges (for inspection)
  python nice_toolkit.py --outdir out graph

  # 3. Gap analysis
  python nice_toolkit.py --outdir out gap --current out/current_roles.txt --target out/target_roles.txt --focus soc

  # 4. Team recommendation with budget
  python nice_toolkit.py --outdir out recommend --focus soc --top 8 --budget 250000 --costs out/roles_costs.csv

  # 5. Risk simulation
  python nice_toolkit.py --outdir out risk --current out/current_roles.txt --scenarios out/risk_scenarios.json --costs out/roles_costs.csv --focus soc --top 8

  # 6. Full 2-year plan + dashboard (all-in-one)
  python nice_toolkit.py --outdir out plan --current out/current_roles.txt --scenarios out/risk_scenarios.json --costs out/roles_costs.csv --focus soc --top 8 --budget 250000
""",
    )
    ap.add_argument("--url", default=URL_DEFAULT, help="NICE Framework JSON URL")
    ap.add_argument("--outdir", default="out", help="Output directory")
    ap.add_argument(
        "--depth", type=int, default=5, help="BFS depth for coverage traversal"
    )

    sub = ap.add_subparsers(dest="cmd", required=True)

    # init
    sub.add_parser(
        "init",
        help="Bootstrap sample data files (roles_costs.csv, risk_scenarios.json, etc.)",
    )

    # graph
    sub.add_parser("graph", help="Export edges TSV")

    # gap
    sg = sub.add_parser("gap", help="Gap analysis")
    sg.add_argument(
        "--current", required=True, help="File with current role IDs (one per line)"
    )
    sg.add_argument(
        "--target", required=True, help="File with target role IDs (one per line)"
    )
    sg.add_argument("--focus", choices=["soc", "grc"], default="soc")

    # recommend
    sr = sub.add_parser("recommend", help="Multi-objective team recommendation")
    sr.add_argument("--focus", choices=["soc", "grc"], required=True)
    sr.add_argument("--top", type=int, default=8)
    sr.add_argument("--budget", type=float, default=250_000)
    sr.add_argument("--costs", help="Path to roles_costs.csv")

    # risk
    srisk = sub.add_parser("risk", help="Risk scenario simulation")
    srisk.add_argument("--current", required=True)
    srisk.add_argument("--scenarios", required=True, help="Path to risk_scenarios.json")
    srisk.add_argument("--costs", help="Path to roles_costs.csv")
    srisk.add_argument("--focus", choices=["soc", "grc"], default="soc")
    srisk.add_argument("--top", type=int, default=8)
    srisk.add_argument("--budget", type=float, default=250_000)

    # plan
    splan = sub.add_parser("plan", help="Full 2-year CISO plan + dashboard")
    splan.add_argument("--current", required=True)
    splan.add_argument("--scenarios", required=True)
    splan.add_argument("--costs", required=True)
    splan.add_argument("--focus", choices=["soc", "grc"], default="soc")
    splan.add_argument("--top", type=int, default=8)
    splan.add_argument("--budget", type=float, default=250_000)

    args = ap.parse_args()
    outdir = Path(args.outdir)

    if args.cmd == "init":
        bootstrap_sample_data(outdir)
        print("Done. Edit the files in", outdir, "then run the other commands.")
        return

    print("Loading NICE Framework data…")
    elements, root = load_nodes(args.url)
    nodes = build_node_index(elements)
    edges = build_edges(root, nodes)
    adj = build_adjacency(edges)
    print(f"  Loaded {len(nodes)} nodes, {len(edges)} edges")

    if args.cmd == "graph":
        out = outdir / "nice_edges.tsv"
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            f.write("src\tdst\tsrc_type\tdst_type\n")
            for s, t in sorted(edges):
                f.write(f"{s}\t{t}\t{nodes[s].type}\t{nodes[t].type}\n")
        print(f"  Edges → {out} (edges={len(edges)})")

    elif args.cmd == "gap":
        cur = parse_role_ids(Path(args.current))
        tgt = parse_role_ids(Path(args.target))
        out = outdir / "nice_gap_report.md"
        export_gap_report(out, nodes, adj, cur, tgt, depth=args.depth, focus=args.focus)

    elif args.cmd == "recommend":
        costs_path = Path(args.costs) if args.costs else None
        picks = recommend(
            nodes,
            adj,
            focus=args.focus,
            top_n=args.top,
            depth=args.depth,
            budget=args.budget,
            costs_path=costs_path,
        )
        out = outdir / f"nice_team_{args.focus}.md"
        export_reco_md(
            out,
            nodes,
            picks,
            adj,
            focus=args.focus,
            budget=args.budget,
            depth=args.depth,
        )

    elif args.cmd == "risk":
        cur = parse_role_ids(Path(args.current))
        costs_path = Path(args.costs) if args.costs else None
        picks = recommend(
            nodes,
            adj,
            focus=args.focus,
            top_n=args.top,
            depth=args.depth,
            budget=args.budget,
            costs_path=costs_path,
        )
        scenarios = load_risk_scenarios(Path(args.scenarios))
        plan_roles = {p["role_id"] for p in picks}
        out = outdir / "nice_risk_report.md"
        simulate_risk(out, nodes, adj, cur, plan_roles, scenarios, depth=args.depth)

    elif args.cmd == "plan":
        cur = parse_role_ids(Path(args.current))
        costs_path = Path(args.costs)
        picks = recommend(
            nodes,
            adj,
            focus=args.focus,
            top_n=args.top,
            depth=args.depth,
            budget=args.budget,
            costs_path=costs_path,
        )
        scenarios = load_risk_scenarios(Path(args.scenarios))
        plan_roles = {p["role_id"] for p in picks}

        export_plan(
            outdir / "nice_plan_2yr.md",
            nodes,
            adj,
            cur,
            picks,
            focus=args.focus,
            budget=args.budget,
            depth=args.depth,
        )

        simulate_risk(
            outdir / "nice_risk_report.md",
            nodes,
            adj,
            cur,
            plan_roles,
            scenarios,
            depth=args.depth,
        )

        export_reco_md(
            outdir / f"nice_team_{args.focus}.md",
            nodes,
            picks,
            adj,
            focus=args.focus,
            budget=args.budget,
            depth=args.depth,
        )

        export_gap_report(
            outdir / "nice_gap_report.md",
            nodes,
            adj,
            cur,
            cur | plan_roles,
            depth=args.depth,
            focus=args.focus,
        )

        export_dashboard(
            outdir / "dashboard.html",
            nodes,
            adj,
            cur,
            picks,
            scenarios,
            focus=args.focus,
            budget=args.budget,
            depth=args.depth,
        )

        total_cost = sum(p["cost_2yr"] for p in picks)
        print(f"\n✅ Full plan generated in: {outdir}/")
        print(
            f"   Roles selected: {len(picks)} | Total cost: ${total_cost:,.0f} / ${args.budget:,.0f}"
        )
        print(f"   Open {outdir}/dashboard.html in a browser to explore the results.")


if __name__ == "__main__":
    main()
