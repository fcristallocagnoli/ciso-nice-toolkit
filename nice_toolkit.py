#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, json, random, re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen

URL_DEFAULT = "https://csrc.nist.gov/csrc/media/Projects/cprt/documents/nice/cprt_SP_800_181_2_1_0_12-11-2025.json"

# -------------------------- Data model --------------------------


@dataclass(frozen=True)
class Node:
    id: str  # element_identifier
    type: str  # element_type
    title: str  # title
    text: str  # text


# -------------------------- Load --------------------------


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


# -------------------------- Relationship extraction (semantic) --------------------------


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
                score = 0
                for it in sample:
                    vals = [
                        vv
                        for vv in it.values()
                        if isinstance(vv, str) and looks_like_id(vv)
                    ]
                    if len(vals) >= 2:
                        score += 1
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
            for s, t in extract_pairs(rel):
                edges.add((s, t))

    return edges


def build_adjacency(edges: Set[Tuple[str, str]]) -> Dict[str, Set[str]]:
    adj: Dict[str, Set[str]] = {}
    for s, t in edges:
        adj.setdefault(s, set()).add(t)
    return adj


# -------------------------- Traversal: Role → Task → Skill → Knowledge --------------------------


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
    role_id: str, adj: Dict[str, Set[str]], nodes: Dict[str, Node], depth: int = 5
) -> Dict[str, Set[str]]:
    return {
        "tasks": bfs_to_types(role_id, adj, nodes, {"task"}, max_depth=depth),
        "skills": bfs_to_types(role_id, adj, nodes, {"skill"}, max_depth=depth),
        "knowledge": bfs_to_types(role_id, adj, nodes, {"knowledge"}, max_depth=depth),
    }


# -------------------------- 2) Quiz: given a task → which role? --------------------------


def moodle_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def export_moodle_task2role_quiz(
    outpath: Path,
    nodes: Dict[str, Node],
    adj: Dict[str, Set[str]],
    num_q: int = 30,
    choices: int = 4,
    seed: int = 10,
    depth: int = 5,
) -> None:
    random.seed(seed)

    roles = [
        nid
        for nid, n in nodes.items()
        if n.type == "work_role" and re.match(r"^[A-Z]{2}-WRL-\d{3}$", nid)
    ]
    tasks = [nid for nid, n in nodes.items() if n.type == "task"]

    # reverse map: task -> roles that can reach it
    task_to_roles: Dict[str, List[str]] = {}
    for r in roles:
        cov = role_coverage(r, adj, nodes, depth=depth)
        for t in cov["tasks"]:
            task_to_roles.setdefault(t, []).append(r)

    candidate_tasks = [t for t in tasks if t in task_to_roles]
    random.shuffle(candidate_tasks)
    picked = candidate_tasks[: min(num_q, len(candidate_tasks))]

    xml = ['<?xml version="1.0" encoding="UTF-8"?>', "<quiz>"]

    for i, tid in enumerate(picked, start=1):
        correct = random.choice(task_to_roles[tid])
        correct_node = nodes[correct]

        # distractors: other roles (same category if possible)
        cat = correct.split("-")[0]
        same_cat = [r for r in roles if r != correct and r.startswith(cat + "-")]
        pool = (
            same_cat
            if len(same_cat) >= choices - 1
            else [r for r in roles if r != correct]
        )
        distract = random.sample(pool, k=choices - 1)

        answers = distract + [correct]
        random.shuffle(answers)

        task_node = nodes[tid]
        qname = f"NICE Task→Role {i:03d}"
        qtext = f"Given the following NICE Task, which NICE Work Role is the best match?<br><br><b>{task_node.id}</b>: {moodle_escape(task_node.text or task_node.title)}"

        xml.append('<question type="multichoice">')
        xml.append(f"<name><text>{moodle_escape(qname)}</text></name>")
        xml.append(
            f'<questiontext format="html"><text><![CDATA[{qtext}]]></text></questiontext>'
        )
        xml.append("<defaultgrade>1.0000000</defaultgrade>")
        xml.append("<penalty>0.3333333</penalty>")
        xml.append("<single>true</single>")
        xml.append("<shuffleanswers>true</shuffleanswers>")
        xml.append("<answernumbering>abc</answernumbering>")

        for rid in answers:
            n = nodes[rid]
            fraction = "100" if rid == correct else "0"
            label = f"{moodle_escape(n.title)} ({rid})"
            fb = (
                moodle_escape(correct_node.text)
                if rid == correct
                else f"Correct: {moodle_escape(correct_node.title)} ({correct})"
            )
            xml.append(
                f'<answer fraction="{fraction}" format="html"><text><![CDATA[{label}]]></text><feedback format="html"><text><![CDATA[{fb}]]></text></feedback></answer>'
            )

        xml.append("</question>")

    xml.append("</quiz>")
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(xml), encoding="utf-8")


# -------------------------- 3) Gap analysis (Tasks/Skills/Knowledge coverage) --------------------------


def parse_role_ids(path: Path) -> Set[str]:
    ids: Set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if re.match(r"^[A-Z]{2}-WRL-\d{3}$", line):
            ids.add(line)
    return ids


def export_gap_report(
    outpath: Path,
    nodes: Dict[str, Node],
    adj: Dict[str, Set[str]],
    current: Set[str],
    target: Set[str],
    depth: int = 5,
) -> None:
    def cov(role_set: Set[str]) -> Dict[str, Set[str]]:
        T, S, K = set(), set(), set()
        for r in role_set:
            if r not in nodes:
                continue
            c = role_coverage(r, adj, nodes, depth=depth)
            T |= c["tasks"]
            S |= c["skills"]
            K |= c["knowledge"]
        return {"tasks": T, "skills": S, "knowledge": K}

    cur = cov(current)
    tgt = cov(target)

    gapT = tgt["tasks"] - cur["tasks"]
    gapS = tgt["skills"] - cur["skills"]
    gapK = tgt["knowledge"] - cur["knowledge"]

    def title(rid: str) -> str:
        return nodes[rid].title if rid in nodes else rid

    lines = []
    lines.append("# NICE Workforce Gap Analysis (semantic)")
    lines.append("")
    lines.append("## Role delta")
    lines.append(
        "**Add (Target \\ Current):** "
        + ", ".join([f"{title(r)} ({r})" for r in sorted(target - current)])
        or "(none)"
    )
    lines.append(
        "**Remove (Current \\ Target):** "
        + ", ".join([f"{title(r)} ({r})" for r in sorted(current - target)])
        or "(none)"
    )
    lines.append("")
    lines.append("## Coverage delta")
    lines.append(
        f"- Tasks: current={len(cur['tasks'])} target={len(tgt['tasks'])} gap={len(gapT)}"
    )
    lines.append(
        f"- Skills: current={len(cur['skills'])} target={len(tgt['skills'])} gap={len(gapS)}"
    )
    lines.append(
        f"- Knowledge: current={len(cur['knowledge'])} target={len(tgt['knowledge'])} gap={len(gapK)}"
    )
    lines.append("")
    lines.append("## Top missing Tasks (first 15)")
    for tid in list(sorted(gapT))[:15]:
        n = nodes.get(tid)
        lines.append(f"- {tid}: {(n.text or n.title) if n else ''}")
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(lines), encoding="utf-8")


# -------------------------- 4) Recommender (SOC / GRC) based on coverage --------------------------


def recommend(
    elements_nodes: Dict[str, Node],
    adj: Dict[str, Set[str]],
    focus: str,
    top_n: int = 8,
    depth: int = 5,
) -> List[str]:
    roles = [
        nid
        for nid, n in elements_nodes.items()
        if n.type == "work_role" and re.match(r"^[A-Z]{2}-WRL-\d{3}$", nid)
    ]

    # Define required capability types per focus (coverage-first)
    focus = focus.lower()
    if focus == "soc":
        want_tasks = {"task"}  # we’ll maximize task coverage (operational)
        want_role_prefix = {"PD", "IN", "IO"}  # allow ops/IR/investigation
    elif focus == "grc":
        want_tasks = {"task"}  # still tasks, but we will bias OG/DD
        want_role_prefix = {"OG", "DD"}
    else:
        raise ValueError("focus must be soc or grc")

    # Greedy set cover over tasks reachable
    role_tasks: Dict[str, Set[str]] = {}
    for r in roles:
        pref = r.split("-")[0]
        if pref not in want_role_prefix:
            continue
        role_tasks[r] = role_coverage(r, adj, elements_nodes, depth=depth)["tasks"]

    chosen: List[str] = []
    covered: Set[str] = set()

    for _ in range(top_n):
        best = None
        best_gain = 0
        for r, tset in role_tasks.items():
            if r in chosen:
                continue
            gain = len(tset - covered)
            if gain > best_gain:
                best_gain = gain
                best = r
        if not best or best_gain == 0:
            break
        chosen.append(best)
        covered |= role_tasks[best]

    return chosen


def export_reco_md(
    outpath: Path,
    nodes: Dict[str, Node],
    picks: List[str],
    adj: Dict[str, Set[str]],
    depth: int = 5,
) -> None:
    lines = ["# NICE Team Recommendation (semantic)", ""]
    total_tasks = set()
    for r in picks:
        lines.append(f"- **{nodes[r].title}** ({r})")
        total_tasks |= role_coverage(r, adj, nodes, depth=depth)["tasks"]
    lines.append("")
    lines.append(f"**Total unique Tasks covered:** {len(total_tasks)}")
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(lines), encoding="utf-8")


# -------------------------- CLI --------------------------


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=URL_DEFAULT)
    ap.add_argument("--outdir", default="out")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub_graph = sub.add_parser("graph")
    sub_graph.add_argument("--outfile", default="nice_edges.tsv")

    sub_quiz = sub.add_parser("quiz-task2role")
    sub_quiz.add_argument("--num-questions", type=int, default=30)
    sub_quiz.add_argument("--choices", type=int, default=4)
    sub_quiz.add_argument("--seed", type=int, default=10)

    sub_gap = sub.add_parser("gap")
    sub_gap.add_argument("--current", required=True)
    sub_gap.add_argument("--target", required=True)

    sub_rec = sub.add_parser("recommend")
    sub_rec.add_argument("--focus", choices=["soc", "grc"], required=True)
    sub_rec.add_argument("--top", type=int, default=8)

    args = ap.parse_args()
    outdir = Path(args.outdir)

    elements, root = load_nodes(args.url)
    nodes = build_node_index(elements)
    edges = build_edges(root, nodes)
    adj = build_adjacency(edges)

    if args.cmd == "graph":
        # export edges for inspection
        out = outdir / args.outfile
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            f.write("src\tdst\tsrc_type\tdst_type\n")
            for s, t in sorted(edges):
                f.write(f"{s}\t{t}\t{nodes[s].type}\t{nodes[t].type}\n")
        print(f"OK: wrote {out} (edges={len(edges)}, nodes={len(nodes)})")

    elif args.cmd == "quiz-task2role":
        out = outdir / "nice_task2role_quiz.xml"
        export_moodle_task2role_quiz(
            out,
            nodes,
            adj,
            num_q=args.num_questions,
            choices=args.choices,
            seed=args.seed,
        )
        print(f"OK: wrote {out}")

    elif args.cmd == "gap":
        cur = parse_role_ids(Path(args.current))
        tgt = parse_role_ids(Path(args.target))
        out = outdir / "nice_gap_report.md"
        export_gap_report(out, nodes, adj, cur, tgt)
        print(f"OK: wrote {out}")

    elif args.cmd == "recommend":
        picks = recommend(nodes, adj, focus=args.focus, top_n=args.top)
        out = outdir / f"nice_team_{args.focus}.md"
        export_reco_md(out, nodes, picks, adj)
        print(f"OK: wrote {out}")


if __name__ == "__main__":
    main()


# python nice_toolkit.py quiz-task2role --num-questions 30 --choices 3

# python nice_toolkit.py gap --current ./out/current_roles.txt --target ./out/target_roles.txt

# Security Operations Center (SOC) focuses on monitoring, detecting, and responding to cybersecurity incidents.
# python nice_toolkit.py recommend --focus soc --top 8

# GRC significa Governance, Risk and Compliance.
# python nice_toolkit.py recommend --focus grc --top 8
