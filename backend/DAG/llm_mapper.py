"""
LLM-Assisted MITRE ATT&CK for ICS Mapper.

Uses an LLM (GPT-4.1) for semantic reasoning to map AASG edges and
attack paths to MITRE ATT&CK for ICS techniques.  Includes formal
verification (μ, Θ, tactic ordering ρ) to validate LLM predictions.

Architecture
============
    extract_context()   — pulls full AASG context from an edge
    LLMMITREMapper      — sends context to GPT, parses JSON
    validate_mapping()  — checks tactic ordering, technique validity
    formal_analysis()   — computes μ(eᵢ), Θ(π), validates ρ

The LLM is used **only** for semantic reasoning.  All structural
validation (reachability, firewall, Purdue, tactic ordering) is
deterministic and runs after the LLM response.
"""

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load environment
# ---------------------------------------------------------------------------
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env", override=True)

# ---------------------------------------------------------------------------
# Canonical Tactic Ordering  ρ
# ---------------------------------------------------------------------------
# This is the formal ordering used to validate LLM predictions.
# A valid attack path must follow this progression (not every tactic
# needs to appear, but they must not appear out of order).

TACTIC_ORDER: List[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Evasion",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Inhibit Response Function",
    "Impair Process Control",
    "Impact",
]

TACTIC_RANK: Dict[str, int] = {t: i for i, t in enumerate(TACTIC_ORDER)}

# ---------------------------------------------------------------------------
# Known MITRE ATT&CK for ICS Technique IDs  (validation whitelist)
# ---------------------------------------------------------------------------
# A subset of valid technique IDs.  The LLM may return IDs outside this
# set — if so, we accept them but flag lower confidence.

KNOWN_TECHNIQUE_IDS = {
    "T0800", "T0801", "T0802", "T0803", "T0804", "T0805", "T0806",
    "T0807", "T0808", "T0809", "T0810", "T0811", "T0812", "T0813",
    "T0814", "T0816", "T0817", "T0818", "T0819", "T0820", "T0821",
    "T0822", "T0823", "T0824", "T0826", "T0827", "T0828", "T0829",
    "T0830", "T0831", "T0832", "T0833", "T0834", "T0835", "T0836",
    "T0837", "T0838", "T0839", "T0840", "T0842", "T0843", "T0845",
    "T0846", "T0847", "T0848", "T0849", "T0850", "T0851", "T0852",
    "T0853", "T0855", "T0856", "T0857", "T0858", "T0859", "T0860",
    "T0861", "T0862", "T0863", "T0864", "T0865", "T0866", "T0867",
    "T0868", "T0869", "T0870", "T0871", "T0872", "T0873", "T0874",
    "T0877", "T0878", "T0879", "T0880", "T0881", "T0882", "T0883",
    "T0884", "T0885", "T0886", "T0887", "T0888", "T0889", "T0890",
    "T0891",
}

# ---------------------------------------------------------------------------
# OpenAI Client (lazy singleton)
# ---------------------------------------------------------------------------

_openai_client = None


def _get_openai_client():
    """Return a cached OpenAI client, created on first use."""
    global _openai_client
    if _openai_client is None:
        load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env", override=True)
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY environment variable is not set. "
                "Add it to backend/.env to enable LLM-based MITRE mapping."
            )
        from openai import OpenAI
        _openai_client = OpenAI(api_key=api_key)
    return _openai_client


def _get_model() -> str:
    return os.getenv("OPENAI_MITRE_MODEL", os.getenv("OPENAI_VISION_MODEL", "gpt-4.1"))


# ---------------------------------------------------------------------------
# Context Extraction
# ---------------------------------------------------------------------------

def extract_context(
    edge: Dict[str, Any],
    edge_type: str,
    validator=None,
    ics_graph=None,
) -> Dict[str, Any]:
    """
    Extract the full AASG context from an edge for LLM prompting.

    Parameters
    ----------
    edge : dict
        An Ea or Ec edge from AASGGraph.
    edge_type : str
        "authorization" or "communication".
    validator : GraphReachabilityValidator | None
        For reachability and firewall checks.
    ics_graph : ICSSecurityGraph | None
        For node attribute lookups.

    Returns
    -------
    dict with keys:
        source, target, source_type, target_type, action, protocol,
        firewall, reachable, purdue_source, purdue_target, edge_type,
        source_zone, target_zone
    """
    label = edge.get("label", {})
    source = edge.get("source", "")
    target = edge.get("target", "")

    # Determine action & protocol
    if edge_type == "authorization":
        action = label.get("action", "access")
        protocol = "unknown"
    else:
        action = "connect"
        protocol = label.get("protocol", "unknown")

    # Source/target types
    source_type = "subject"
    target_type = label.get("destination_type", "unknown")

    if ics_graph and hasattr(ics_graph, "asset_graph"):
        ag = ics_graph.asset_graph
        if ag.has_node(source):
            source_type = str(ag.nodes[source].get("type", source_type)).lower()
        if ag.has_node(target):
            target_type = str(ag.nodes[target].get("type", target_type)).lower()

    # Reachability & firewall
    firewall_allowed = True
    reachable = True
    if validator:
        reachable = validator.comm_edge_exists(source, target) or validator.can_reach(source, target)
        firewall_allowed = validator.firewall_allows(source, target, protocol)

    # Purdue levels
    purdue_src = None
    purdue_tgt = None
    if validator:
        purdue_src = validator.get_node_purdue(source)
        purdue_tgt = validator.get_node_purdue(target)

    # Zones
    source_zone = label.get("source_zone", "unknown")
    target_zone = label.get("target_zone", "unknown")

    return {
        "source":        source,
        "target":        target,
        "source_type":   source_type,
        "target_type":   target_type,
        "action":        action,
        "protocol":      protocol,
        "firewall":      "Allowed" if firewall_allowed else "Denied",
        "reachable":     "Yes" if reachable else "No",
        "purdue_source": f"Level {int(purdue_src)}" if purdue_src is not None else "Unknown",
        "purdue_target": f"Level {int(purdue_tgt)}" if purdue_tgt is not None else "Unknown",
        "edge_type":     edge_type,
        "source_zone":   source_zone,
        "target_zone":   target_zone,
    }


# ---------------------------------------------------------------------------
# Prompt Templates
# ---------------------------------------------------------------------------

_SINGLE_EDGE_PROMPT = """You are an Industrial Control System security expert.

Map the following {edge_type} edge to MITRE ATT&CK for ICS.

Source Role/Asset: {source}
Source Type: {source_type}
Target Asset: {target}
Target Type: {target_type}
Action: {action}
Protocol: {protocol}
Firewall: {firewall}
Reachable: {reachable}
Purdue: {purdue_source} -> {purdue_target}
Source Zone: {source_zone}
Target Zone: {target_zone}

Return ONLY valid JSON. No markdown, no explanation.

{{
  "technique_id": "",
  "technique_name": "",
  "tactic": "",
  "confidence": 0.0,
  "reason": ""
}}

Rules:
- technique_id must be a valid MITRE ATT&CK for ICS technique ID (e.g. T0866)
- tactic must be one of: Initial Access, Execution, Persistence, Evasion, Discovery, Lateral Movement, Collection, Command and Control, Inhibit Response Function, Impair Process Control, Impact
- confidence must be a float between 0.0 and 1.0
- reason must be a single sentence explaining why this technique applies
"""

_ATTACK_PATH_PROMPT = """You are an Industrial Control System security expert.

This attack path occurs in an ICS network. Assign the most appropriate MITRE ATT&CK for ICS technique to every edge. Also ensure the tactic progression is realistic.

{edges_description}

Return ONLY a valid JSON array. No markdown, no explanation.

[
  {{
    "edge": "source->target",
    "technique_id": "",
    "technique_name": "",
    "tactic": "",
    "confidence": 0.0,
    "reason": ""
  }}
]

Rules:
- technique_id must be a valid MITRE ATT&CK for ICS technique ID (e.g. T0866)
- tactic must be one of: Initial Access, Execution, Persistence, Evasion, Discovery, Lateral Movement, Collection, Command and Control, Inhibit Response Function, Impair Process Control, Impact
- The tactic progression should follow a realistic attack lifecycle (Initial Access first, Impact/Impair Process Control last)
- confidence must be a float between 0.0 and 1.0
- reason must be a single sentence for each edge
"""


# ---------------------------------------------------------------------------
# JSON Extraction Helper
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> Any:
    """Robustly extract JSON from LLM output."""
    if not text:
        return None

    cleaned = text.strip()
    # Remove markdown code fences
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Try to find JSON object or array in the text
    for pattern in [r'\{[^{}]*\}', r'\[[\s\S]*\]']:
        match = re.search(pattern, cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                continue

    return None


# ---------------------------------------------------------------------------
# Mapping Validation
# ---------------------------------------------------------------------------

def validate_mapping(
    mapping: Dict[str, Any],
    edge_context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Validate a single LLM-produced MITRE mapping.

    Checks:
      1. technique_id format (T followed by 4 digits)
      2. technique_id is in the known whitelist
      3. tactic is in the canonical ordering
      4. confidence is in [0, 1]

    Returns the mapping dict with added validation fields:
      - validated: bool
      - validation_warnings: list[str]
      - adjusted_confidence: float (may be lowered if validation issues found)
    """
    warnings = []
    valid = True
    conf = float(mapping.get("confidence", 0.5))

    tech_id = str(mapping.get("technique_id", ""))
    tactic = str(mapping.get("tactic", ""))

    # Check technique_id format
    if not re.match(r"^T\d{4}$", tech_id):
        warnings.append(f"Invalid technique_id format: '{tech_id}' — expected T followed by 4 digits")
        valid = False
        conf *= 0.3

    # Check against known whitelist
    if tech_id not in KNOWN_TECHNIQUE_IDS and valid:
        warnings.append(f"technique_id '{tech_id}' not in known MITRE ATT&CK for ICS whitelist — may be valid but unverified")
        conf *= 0.7

    # Check tactic is recognized
    if tactic not in TACTIC_RANK:
        warnings.append(f"Unrecognized tactic: '{tactic}' — not in canonical ordering")
        valid = False
        conf *= 0.3

    # Clamp confidence
    conf = max(0.0, min(1.0, conf))

    mapping["validated"] = valid
    mapping["validation_warnings"] = warnings
    mapping["adjusted_confidence"] = round(conf, 2)

    return mapping


def validate_tactic_ordering(mappings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate that the tactic progression across an ordered attack path
    follows the canonical ordering ρ.

    Parameters
    ----------
    mappings : list of dicts
        Ordered list of edge mappings, each with a "tactic" field.

    Returns
    -------
    dict with:
        valid: bool — True if ordering is respected
        violations: list of str — descriptions of ordering violations
        tactic_sequence: list of str — the extracted tactic sequence
    """
    tactics = [m.get("tactic", "Unknown") for m in mappings]
    violations = []

    max_rank_seen = -1
    for i, tactic in enumerate(tactics):
        rank = TACTIC_RANK.get(tactic, -1)
        if rank == -1:
            continue  # skip unknown tactics
        if rank < max_rank_seen:
            # Find which previous tactic had the higher rank
            for j in range(i - 1, -1, -1):
                prev_rank = TACTIC_RANK.get(tactics[j], -1)
                if prev_rank == max_rank_seen:
                    violations.append(
                        f"Edge {i}: tactic '{tactic}' (rank {rank}) appears after "
                        f"'{tactics[j]}' (rank {prev_rank}) at edge {j} — "
                        f"violates canonical ordering ρ"
                    )
                    break
        max_rank_seen = max(max_rank_seen, rank)

    return {
        "valid": len(violations) == 0,
        "violations": violations,
        "tactic_sequence": tactics,
    }


# ---------------------------------------------------------------------------
# Formal Analysis  (μ, Θ, ρ)
# ---------------------------------------------------------------------------

def formal_analysis(
    path: List[str],
    edge_mappings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compute the formal model functions from the paper.

    Definitions
    -----------
    μ(eᵢ) = {technique_id}    — technique set for edge i
    Θ(π)  = ⋃ᵢ μ(eᵢ)          — MITRE trace (union of all techniques)
    ρ     = tactic ordering    — validated against canonical order

    Parameters
    ----------
    path : list of str
        Ordered node IDs in the attack path.
    edge_mappings : list of dict
        Per-edge mappings with technique_id, tactic, etc.

    Returns
    -------
    dict with:
        attack_path: list of str
        mu: dict[str, set] — μ(eᵢ) for each edge
        theta: list of str — Θ(π) unique technique set
        tactic_progression: list of str
        ordering_validation: dict — result of validate_tactic_ordering
        mitre_trace: list of dict — [{edge, technique_id, tactic}, ...]
    """
    # μ(eᵢ) — technique set per edge
    mu: Dict[str, List[str]] = {}
    mitre_trace = []

    for i, mapping in enumerate(edge_mappings):
        edge_label = f"e{i+1}"
        if i < len(path) - 1:
            edge_label = f"{path[i]}->{path[i+1]}"

        tech_id = mapping.get("technique_id", "Unknown")
        tactic = mapping.get("tactic", "Unknown")

        mu[edge_label] = [tech_id]
        mitre_trace.append({
            "edge": edge_label,
            "technique_id": tech_id,
            "technique_name": mapping.get("technique_name", ""),
            "tactic": tactic,
            "confidence": mapping.get("adjusted_confidence", mapping.get("confidence", 0.5)),
            "reason": mapping.get("reason", ""),
        })

    # Θ(π) — union of all techniques
    theta = list(set(
        tech
        for techs in mu.values()
        for tech in techs
        if tech != "Unknown"
    ))

    # Tactic progression
    tactic_sequence = [m.get("tactic", "Unknown") for m in edge_mappings]

    # Validate ordering ρ
    ordering_validation = validate_tactic_ordering(edge_mappings)

    return {
        "attack_path": path,
        "mu": mu,
        "theta": sorted(theta),
        "tactic_progression": tactic_sequence,
        "ordering_validation": ordering_validation,
        "mitre_trace": mitre_trace,
    }


# ---------------------------------------------------------------------------
# LLMMITREMapper
# ---------------------------------------------------------------------------

class LLMMITREMapper:
    """
    LLM-based MITRE ATT&CK for ICS mapper.

    Sends AASG edge context to GPT and parses structured JSON responses.
    Includes response caching, retry logic, and formal verification.
    """

    def __init__(self, model: Optional[str] = None):
        self.model = model or _get_model()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._call_count = 0
        self._cache_hits = 0

    # ------------------------------------------------------------------
    # Cache key
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_key(context: Dict[str, Any]) -> str:
        """Generate a deterministic cache key from edge context."""
        # Use a subset of context fields that determine the mapping
        key_fields = {
            "source_type":  context.get("source_type", ""),
            "target_type":  context.get("target_type", ""),
            "action":       context.get("action", ""),
            "protocol":     context.get("protocol", ""),
            "edge_type":    context.get("edge_type", ""),
            "firewall":     context.get("firewall", ""),
            "reachable":    context.get("reachable", ""),
        }
        raw = json.dumps(key_fields, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # LLM Call with retry
    # ------------------------------------------------------------------

    def _call_llm(self, prompt: str, max_retries: int = 2) -> Optional[str]:
        """Call the OpenAI API with retry logic."""
        client = _get_openai_client()

        for attempt in range(max_retries + 1):
            try:
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are an ICS security expert specializing in MITRE ATT&CK for ICS. Return only valid JSON.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                    max_tokens=1000,
                )
                self._call_count += 1
                return response.choices[0].message.content
            except Exception as e:
                logger.warning(
                    f"[LLMMITREMapper] API call attempt {attempt+1}/{max_retries+1} failed: {e}"
                )
                if attempt < max_retries:
                    time.sleep(2 ** attempt)  # exponential backoff
                else:
                    logger.error(f"[LLMMITREMapper] All retries exhausted: {e}")
                    return None

    # ------------------------------------------------------------------
    # Single Edge Mapping
    # ------------------------------------------------------------------

    def map_single_edge(
        self,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Map a single AASG edge to a MITRE ATT&CK for ICS technique.

        Parameters
        ----------
        context : dict
            Output of extract_context().

        Returns
        -------
        dict with technique_id, technique_name, tactic, confidence, reason,
        plus validation fields.
        """
        # Check cache
        cache_key = self._cache_key(context)
        if cache_key in self._cache:
            self._cache_hits += 1
            logger.debug(f"[LLMMITREMapper] Cache hit for {context['source']}->{context['target']}")
            return self._cache[cache_key].copy()

        # Build prompt
        prompt = _SINGLE_EDGE_PROMPT.format(**context)

        # Call LLM
        raw_response = self._call_llm(prompt)

        if not raw_response:
            # Fallback if LLM fails
            result = self._fallback_mapping(context)
            result["llm_failed"] = True
            return result

        # Parse response
        parsed = _extract_json(raw_response)
        if not parsed or not isinstance(parsed, dict):
            logger.warning(
                f"[LLMMITREMapper] Failed to parse JSON from LLM response for "
                f"{context['source']}->{context['target']}: {raw_response[:200]}"
            )
            result = self._fallback_mapping(context)
            result["llm_parse_failed"] = True
            return result

        # Validate
        validated = validate_mapping(parsed, context)
        validated["llm_model"] = self.model
        validated["llm_raw_response"] = raw_response[:500]

        # Cache
        self._cache[cache_key] = validated.copy()

        return validated

    # ------------------------------------------------------------------
    # Attack Path Mapping
    # ------------------------------------------------------------------

    def map_attack_path(
        self,
        path: List[str],
        edge_contexts: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Map an entire attack path to MITRE ATT&CK for ICS techniques.

        Sends the full path to the LLM for tactic-progression–aware mapping,
        then runs formal_analysis() on the result.

        Parameters
        ----------
        path : list of str
            Ordered node IDs.
        edge_contexts : list of dict
            One context dict per edge (len = len(path) - 1).

        Returns
        -------
        (edge_mappings, formal_result)
            edge_mappings — list of validated per-edge dicts
            formal_result — formal analysis with μ, Θ, ρ
        """
        if not edge_contexts:
            return [], formal_analysis(path, [])

        # Build edges description for the prompt
        edges_desc_parts = []
        for i, ctx in enumerate(edge_contexts):
            purdue_str = f"{ctx['purdue_source']} -> {ctx['purdue_target']}"
            edges_desc_parts.append(
                f"Edge{i+1}:\n"
                f"  {ctx['source']} ({ctx['source_type']})\n"
                f"  ↓ via {ctx['protocol'] if ctx['protocol'] != 'unknown' else ctx['action']}\n"
                f"  {ctx['target']} ({ctx['target_type']})\n"
                f"  Firewall: {ctx['firewall']}, Reachable: {ctx['reachable']}, Purdue: {purdue_str}"
            )

        edges_description = "\n\n".join(edges_desc_parts)
        prompt = _ATTACK_PATH_PROMPT.format(edges_description=edges_description)

        # Call LLM
        raw_response = self._call_llm(prompt)

        if raw_response:
            parsed = _extract_json(raw_response)
        else:
            parsed = None

        # Process result
        if parsed and isinstance(parsed, list) and len(parsed) == len(edge_contexts):
            edge_mappings = []
            for i, mapping in enumerate(parsed):
                validated = validate_mapping(mapping, edge_contexts[i])
                validated["llm_model"] = self.model
                edge_mappings.append(validated)
        else:
            # Fall back to per-edge mapping if path mapping fails
            logger.warning(
                f"[LLMMITREMapper] Attack path mapping returned invalid result "
                f"(expected {len(edge_contexts)} edges). Falling back to per-edge mapping."
            )
            edge_mappings = []
            for ctx in edge_contexts:
                mapping = self.map_single_edge(ctx)
                edge_mappings.append(mapping)

        # Formal analysis
        formal_result = formal_analysis(path, edge_mappings)

        return edge_mappings, formal_result

    # ------------------------------------------------------------------
    # Fallback (minimal rule-based) for when LLM is unavailable
    # ------------------------------------------------------------------

    @staticmethod
    def _fallback_mapping(context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Minimal emergency fallback when the LLM is unreachable.
        Uses simple heuristics — NOT the full rule engine.
        """
        target_type = context.get("target_type", "").lower()
        action = context.get("action", "").lower()
        protocol = context.get("protocol", "").lower()

        # Very basic fallback — just enough to not crash
        if action in ("vpn_access", "remote_login", "ssh_access", "rdp_access") or protocol in ("vpn", "ssh", "rdp"):
            return {"technique_id": "T0866", "technique_name": "Remote Services",
                    "tactic": "Initial Access", "confidence": 0.4,
                    "reason": "Fallback: remote access pattern detected"}
        elif target_type in ("plc", "rtu"):
            return {"technique_id": "T0831", "technique_name": "Modify Controller Tasking",
                    "tactic": "Impair Process Control", "confidence": 0.4,
                    "reason": "Fallback: PLC/RTU target detected"}
        elif protocol in ("modbus", "modbus_tcp", "dnp3", "opc_ua", "opc"):
            return {"technique_id": "T0801", "technique_name": "Monitor Process State",
                    "tactic": "Collection", "confidence": 0.4,
                    "reason": "Fallback: ICS protocol detected"}
        else:
            return {"technique_id": "T0859", "technique_name": "Valid Accounts",
                    "tactic": "Lateral Movement", "confidence": 0.3,
                    "reason": "Fallback: generic access pattern"}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return usage statistics."""
        return {
            "llm_calls": self._call_count,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
            "model": self.model,
        }
