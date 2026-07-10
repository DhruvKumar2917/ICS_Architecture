"""
LLM-Assisted MITRE ATT&CK for ICS Mapper.
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

# Load environment
load_dotenv(dotenv_path=Path(__file__).parent.parent.parent / ".env", override=True)

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

_openai_client = None


def _get_openai_client():
    global _openai_client
    if _openai_client is None:
        load_dotenv(dotenv_path=Path(__file__).parent.parent.parent / ".env", override=True)
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


class ContextBuilderAgent:
    def enrich_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        enriched = dict(context)
        enriched["subject"] = enriched.get("source", "")
        enriched["target_object"] = enriched.get("target", "")
        enriched["object_type"] = enriched.get("target_type", "")
        enriched["firewall_status"] = enriched.get("firewall", "Allowed")
        enriched["reachability"] = enriched.get("reachable", "Yes")
        enriched["previous_attack_step"] = enriched.get("previous_node", "None")
        enriched["next_attack_step"] = enriched.get("next_node", "None")
        enriched["role"] = enriched.get("role_provenance", enriched.get("source", "unknown"))
        return enriched


# ACTION_TECHNIQUE_COMPATIBILITY_MATRIX: Maps normalized action names to the set of
# MITRE ATT&CK for ICS technique IDs that are semantically valid for that action.
# IMPORTANT: Keep this list OT-grounded. Do NOT add IT-layer fallbacks here;
# those are handled via ATTACK_ICS_KB.asset_types expansion below.
ACTION_TECHNIQUE_COMPATIBILITY_MATRIX = {
    "manage_accounts":  ["T0886", "T0859", "T0812"],
    "review_logs":      ["T0801", "T0887", "T0884"],
    "file_transfer":    ["T0843", "T0845", "T0834"],
    "modify_firewall":  ["T0814", "T0886"],
    "remote_login":     ["T0866", "T0859", "T0812"],
    "remote_access":    ["T0866", "T0859", "T0812"],
    "vpn_access":       ["T0866", "T0859", "T0812"],
    "ssh_access":       ["T0866", "T0859", "T0812"],
    "rdp_access":       ["T0866", "T0859", "T0812"],
    "send_command":     ["T0831", "T0836", "T0847", "T0834", "T0843"],
    "write_plc":        ["T0831", "T0836", "T0847", "T0834", "T0843"],
    "program_plc":      ["T0831", "T0836", "T0847", "T0834", "T0843"],
    "read_diagnostics": ["T0887", "T0801", "T0877", "T0884", "T0845"],
    "monitor":          ["T0801", "T0877", "T0852"],
    "view":             ["T0801", "T0877", "T0852"],
    "read":             ["T0801", "T0877", "T0852"],
    "shutdown":         ["T0816", "T0881"],
    "restart":          ["T0816", "T0881"],
    "stop":             ["T0816", "T0881"],
    "connect":          ["T0866", "T0859", "T0869"],
    "access":           ["T0866", "T0859", "T0812"],
}


class CandidateSelectionAgent:
    def select_candidates(self, context: Dict[str, Any]) -> List[Dict[str, str]]:
        target_type = str(context.get("object_type", context.get("target_type", ""))).lower()
        action = str(context.get("action", "")).lower()
        protocol = str(context.get("protocol", "")).lower()

        action_norm = action.replace("-", "_").replace(" ", "_")

        all_kb_techniques = []
        for tid, meta in ATTACK_ICS_KB.items():
            all_kb_techniques.append({
                "id": tid,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "asset_types": meta["asset_types"],
                "protocols": meta["protocols"]
            })

        asset_filtered = []
        for t in all_kb_techniques:
            if any(asset in target_type for asset in t["asset_types"]):
                asset_filtered.append(t)
            elif target_type == "unknown" or not target_type:
                asset_filtered.append(t)

        action_filtered = []
        if action_norm in ACTION_TECHNIQUE_COMPATIBILITY_MATRIX:
            allowed_ids = ACTION_TECHNIQUE_COMPATIBILITY_MATRIX[action_norm]
            for t in asset_filtered:
                if t["id"] in allowed_ids:
                    action_filtered.append(t)
        else:
            action_clean = action_norm.replace("_", " ")
            for t in asset_filtered:
                if any(kw in action_clean for kw in ("firewall", "port")) and t["id"] in ("T0814", "T0886"):
                    action_filtered.append(t)
                elif any(kw in action_clean for kw in ("account", "user", "cred")) and t["id"] in ("T0886", "T0859", "T0812"):
                    action_filtered.append(t)
                elif any(kw in action_clean for kw in ("command", "write", "program", "control")) and t["id"] in ("T0831", "T0836", "T0847", "T0834", "T0843"):
                    action_filtered.append(t)
                elif any(kw in action_clean for kw in ("monitor", "read", "view", "diagnostics")) and t["tactic"] in ("Collection", "Discovery"):
                    action_filtered.append(t)
                elif any(kw in action_clean for kw in ("vpn", "login", "access", "connect", "ssh", "rdp")) and t["id"] in ("T0866", "T0859", "T0812", "T0869"):
                    action_filtered.append(t)
            
            if not action_filtered:
                action_filtered = asset_filtered

        protocol_filtered = []
        if protocol and protocol != "unknown":
            for t in action_filtered:
                if any(proto in protocol for proto in t["protocols"]) or "unknown" in t["protocols"]:
                    protocol_filtered.append(t)
            if not protocol_filtered:
                protocol_filtered = action_filtered
        else:
            protocol_filtered = action_filtered

        result = []
        for t in protocol_filtered:
            result.append({
                "id": t["id"],
                "name": t["name"],
                "tactic": t["tactic"]
            })

        if not result:
            # Asset-type-aware fallback: never return IT-only techniques for OT targets.
            ot_types = {"plc", "rtu", "safety_controller", "safety", "sensor", "actuator", "physical_process"}
            is_ot_target = any(ot in target_type for ot in ot_types)
            if is_ot_target:
                result = [
                    {"id": "T0831", "name": "Modify Controller Tasking", "tactic": "Impair Process Control"},
                    {"id": "T0847", "name": "Unauthorized Command Message", "tactic": "Impair Process Control"},
                    {"id": "T0877", "name": "I/O Image", "tactic": "Collection"},
                ]
            else:
                result = [
                    {"id": "T0859", "name": "Valid Accounts", "tactic": "Lateral Movement"},
                    {"id": "T0866", "name": "Remote Services", "tactic": "Initial Access"},
                ]
        return result


_REASONING_AGENT_PROMPT = """You are an Industrial Control System security expert.

Analyze this cyber attack step and map it to the most semantically appropriate MITRE ATT&CK for ICS technique.

=== ATTACK STEP CONTEXT ===
Subject (Attacking Entity/User): {subject}
RBAC Role: {role}
Action Performed: {action}
Protocol Used: {protocol}
Target Object (Asset): {target_object}
Target Object Type: {object_type}
Target Network Zone: {target_zone}
Target Purdue Level: {purdue_target}
Target Criticality: {criticality}
Source Network Zone: {source_zone}
Source Purdue Level: {purdue_source}
Firewall Status: {firewall_status}
Reachability: {reachability}

Previous Attack Step: {previous_attack_step}
Next Attack Step: {next_attack_step}

=== ATTACK CHAIN STAGE ===
The Attack Chain Reasoning Agent has classified this step's stage/role as: {classified_tactic_role}

=== CANDIDATE MITRE ATT&CK FOR ICS TECHNIQUES ===
{candidates_list}

=== TASK ===
Select the best technique from the candidate list. Choose EXACTLY ONE technique.
Ensure the tactic matches the tactic of the selected candidate technique.

ATTEMPTED TECHNIQUE VS EXECUTION OUTCOME:
The selected technique MUST represent what the attacker ATTEMPTED, regardless of whether the connection succeeded or was blocked/unreachable. Do not change the technique choice based on firewall block or reachability status. If the connection was blocked by a firewall or was unreachable, STILL select the technique representing the attempted action, but write in the reason that it was unsuccessful/attempted due to the status, and use a low confidence score (maximum 0.40 for firewall-blocked, 0.30 for unreachable).

COUPLED EXPLANATION GENERATION:
Your selected technique, its tactic, and the reason MUST describe the same adversarial behavior. The justification (reason) must explain the final selected technique, not the original action alone.

In addition, construct a detailed evidence trace dictionary explaining exactly which contextual factors contributed to the decision.

=== OUTPUT FORMAT ===
Return ONLY a valid JSON object. Do not include any markdown formatting, backticks, or extra explanation.

{{
  "technique_id": "TXXXX",
  "technique_name": "Technique Name",
  "tactic": "Tactic Name",
  "confidence": 0.XX,
  "reason": "Detailed justification explaining the intent and behavior of the attempted action.",
  "evidence_trace": {{
    "action_factor": "How the action performed influenced the mapping",
    "object_type_factor": "How the target asset type influenced the mapping",
    "protocol_factor": "How the protocol used influenced the mapping",
    "firewall_status_factor": "How the firewall status influenced the mapping",
    "purdue_level_factor": "How the Purdue level structure influenced the mapping"
  }}
}}
"""


class MITREReasoningAgent:
    def __init__(self, model: str, timeout_sec: float):
        self.model = model
        self.timeout_sec = timeout_sec

    def generate_mapping(
        self,
        context: Dict[str, Any],
        candidates: List[Dict[str, str]],
        feedback: Optional[str] = None,
    ) -> Optional[str]:
        candidates_str = "\n".join(f"- {c['id']}: {c['name']} (Tactic: {c['tactic']})" for c in candidates)

        prompt = _REASONING_AGENT_PROMPT.format(
            subject=context.get("subject", ""),
            role=context.get("role", ""),
            action=context.get("action", ""),
            protocol=context.get("protocol", ""),
            target_object=context.get("target_object", ""),
            object_type=context.get("object_type", ""),
            target_zone=context.get("target_zone", ""),
            purdue_target=context.get("purdue_target", ""),
            criticality=context.get("criticality", ""),
            source_zone=context.get("source_zone", ""),
            purdue_source=context.get("purdue_source", ""),
            firewall_status=context.get("firewall_status", ""),
            reachability=context.get("reachability", ""),
            previous_attack_step=context.get("previous_attack_step", ""),
            next_attack_step=context.get("next_attack_step", ""),
            classified_tactic_role=context.get("classified_tactic_role", "Unknown"),
            candidates_list=candidates_str,
        )

        if feedback:
            prompt += f"\n\n=== REGENERATION FEEDBACK ===\nYour previous attempt was REJECTED due to the following validation errors:\n{feedback}\nPlease correct these errors and provide a revised, compliant mapping."

        client = _get_openai_client()
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an ICS security expert specializing in MITRE ATT&CK for ICS. Return ONLY valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=1000,
                timeout=self.timeout_sec,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"[MITREReasoningAgent] API call failed: {e}")
            return None


class SemanticValidationAgent:
    def validate(
        self,
        mapping: Dict[str, Any],
        context: Dict[str, Any],
        candidates: List[Dict[str, str]],
    ) -> Tuple[bool, List[str]]:
        errors = []

        tech_id = str(mapping.get("technique_id", "")).upper().strip()
        tactic = str(mapping.get("tactic", "")).strip()
        name = str(mapping.get("technique_name", "")).strip()
        reason = str(mapping.get("reason", "")).strip()
        reason_lower = reason.lower()

        if not re.match(r"^T\d{4}$", tech_id):
            errors.append(f"Validation Error: Invalid technique_id format '{tech_id}'. Expected 'T' followed by 4 digits.")
            return False, errors

        candidate_ids = {c["id"] for c in candidates}
        if tech_id not in candidate_ids:
            errors.append(f"Validation Error: Technique ID '{tech_id}' ({name}) is not in the candidate shortlist for this context.")

        # NOTE: We intentionally do NOT re-check ACTION_TECHNIQUE_COMPATIBILITY_MATRIX here.
        # The CandidateSelectionAgent already enforces action-technique compatibility by
        # intersecting the action matrix with the KB asset-type filter. Re-checking the
        # action matrix independently here causes impossible deadlocks when the LLM
        # legitimately selects a candidate that passed asset-type filtering but whose
        # action-matrix entry was too narrow for the actual target asset type.
        # The candidate shortlist is the single authoritative gate.

        target_type = str(context.get("object_type", "")).lower()
        if tech_id in ATTACK_ICS_KB and tech_id in candidate_ids:
            # Only enforce asset-type check for techniques that were NOT in the candidate
            # shortlist (i.e., the LLM went off-list). If the technique was already
            # validated by CandidateSelectionAgent, trust the selection.
            pass  # candidate shortlist guarantees asset-type compatibility
        elif tech_id in ATTACK_ICS_KB and tech_id not in candidate_ids:
            kb_entry = ATTACK_ICS_KB[tech_id]
            if target_type and target_type != "unknown":
                if not any(asset in target_type for asset in kb_entry["asset_types"]):
                    errors.append(f"Validation Error: Technique '{tech_id}' ({kb_entry['name']}) is not supported for asset type '{target_type}'. Supported: {kb_entry['asset_types']}.")

        protocol = str(context.get("protocol", "")).lower()
        if tech_id in ATTACK_ICS_KB and protocol and protocol != "unknown":
            kb_entry = ATTACK_ICS_KB[tech_id]
            if not any(proto in protocol for proto in kb_entry["protocols"]) and "unknown" not in kb_entry["protocols"]:
                errors.append(f"Validation Error: Protocol '{protocol}' is incompatible with technique '{tech_id}'. Supported: {kb_entry['protocols']}.")

        if tech_id == "T0859" and ("remote service" in reason_lower or "vpn" in reason_lower or "ssh" in reason_lower or "rdp" in reason_lower):
            if "account" not in reason_lower and "credential" not in reason_lower and "user" not in reason_lower:
                errors.append("Validation Error: Explanation discusses Remote Services or remote protocols, contradicting the selected technique 'Valid Accounts' (T0859).")
        if tech_id == "T0866" and "valid account" in reason_lower and "remote service" not in reason_lower:
            errors.append("Validation Error: Explanation describes Valid Accounts abuse, contradicting the selected technique 'Remote Services' (T0866).")
        if tech_id == "T0856" and "spoof" not in reason_lower and "report" not in reason_lower:
            errors.append("Validation Error: Selected technique is Spoof Reporting Message (T0856) but the explanation fails to mention spoofing or reporting.")

        firewall_denied = context.get("firewall_status") == "Denied"
        reachable_no = context.get("reachability") == "No"
        success_keywords = ["compromise success", "successfully compromised", "gains access", "gained access", "established connection", "allows connection", "successfully execute"]

        if firewall_denied:
            if any(k in reason_lower for k in success_keywords) and not any(k in reason_lower for k in ["block", "denied", "prevent", "attempt"]):
                errors.append("Validation Error: Firewall status is Denied (blocked), but the explanation claims successful compromise/access.")
            if "block" not in reason_lower and "denied" not in reason_lower and "attempt" not in reason_lower:
                errors.append("Validation Error: Action is blocked by firewall, but justification fails to identify it as unsuccessful/blocked.")
            try:
                conf = float(mapping.get("confidence", 1.0))
                if conf > 0.40:
                    errors.append(f"Validation Error: Firewall is Denied, but confidence score ({conf}) is too high (must be <= 0.40).")
            except ValueError:
                errors.append("Validation Error: Confidence must be a valid float score.")

        if reachable_no:
            if any(k in reason_lower for k in success_keywords) and not any(k in reason_lower for k in ["unreachable", "attempt", "prevent"]):
                errors.append("Validation Error: Target is unreachable, but the explanation claims successful compromise/access.")
            if "unreachable" not in reason_lower and "attempt" not in reason_lower:
                errors.append("Validation Error: Target is unreachable, but justification fails to state it was unreachable/unsuccessful.")
            try:
                conf = float(mapping.get("confidence", 1.0))
                if conf > 0.30:
                    errors.append(f"Validation Error: Target is unreachable, but confidence score ({conf}) is too high (must be <= 0.30).")
            except ValueError:
                errors.append("Validation Error: Confidence must be a valid float score.")

        matching_cand = next((c for c in candidates if c["id"] == tech_id), None)
        if matching_cand and matching_cand["tactic"] != tactic:
            errors.append(f"Validation Error: Selected tactic '{tactic}' does not match candidate tactic '{matching_cand['tactic']}' for technique '{tech_id}'.")

        return len(errors) == 0, errors


ATTACK_ICS_KB = {
    "T0801": {
        "name": "Monitor Process State",
        "tactic": "Collection",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian", "plc", "rtu"],
        "protocols": ["modbus", "modbus_tcp", "dnp3", "opc", "opc_ua", "s7comm", "unknown"]
    },
    "T0812": {
        # Official MITRE ATT&CK for ICS: Default Credentials applies to field devices
        # (PLCs, RTUs, safety controllers) as well as IT-layer assets.
        "name": "Default Credentials",
        "tactic": "Initial Access",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian", "firewall", "vpn", "gateway",
                        "plc", "rtu", "safety_controller", "safety", "sensor", "actuator"],
        "protocols": ["ssh", "rdp", "vpn", "http", "https", "modbus", "modbus_tcp", "dnp3", "s7comm", "unknown"]
    },
    "T0814": {
        "name": "Modify Firewall",
        "tactic": "Evasion",
        "asset_types": ["firewall", "vpn", "gateway", "server", "workstation"],
        "protocols": ["ssh", "rdp", "vpn", "http", "https", "unknown"]
    },
    "T0816": {
        "name": "Device Restart/Shutdown",
        "tactic": "Inhibit Response Function",
        "asset_types": ["plc", "rtu", "safety_controller", "safety", "server", "workstation", "scada", "hmi", "firewall", "vpn", "gateway"],
        "protocols": ["modbus", "modbus_tcp", "dnp3", "opc", "opc_ua", "s7comm", "ssh", "rdp", "unknown"]
    },
    "T0831": {
        "name": "Modify Controller Tasking",
        "tactic": "Impair Process Control",
        "asset_types": ["plc", "rtu", "safety_controller", "safety"],
        "protocols": ["modbus", "modbus_tcp", "dnp3", "opc", "opc_ua", "s7comm", "unknown"]
    },
    "T0834": {
        "name": "Native API",
        "tactic": "Execution",
        "asset_types": ["plc", "rtu", "safety_controller", "safety", "server", "workstation"],
        "protocols": ["s7comm", "unknown"]
    },
    "T0836": {
        "name": "Modify Parameter",
        "tactic": "Impair Process Control",
        "asset_types": ["plc", "rtu", "safety_controller", "safety"],
        "protocols": ["modbus", "modbus_tcp", "dnp3", "opc", "opc_ua", "s7comm", "unknown"]
    },
    "T0843": {
        "name": "Program Download",
        "tactic": "Execution",
        "asset_types": ["plc", "rtu", "safety_controller", "safety"],
        "protocols": ["s7comm", "unknown"]
    },
    "T0845": {
        "name": "Program Upload",
        "tactic": "Collection",
        "asset_types": ["plc", "rtu", "safety_controller", "safety"],
        "protocols": ["s7comm", "unknown"]
    },
    "T0847": {
        "name": "Unauthorized Command Message",
        "tactic": "Impair Process Control",
        "asset_types": ["plc", "rtu", "safety_controller", "safety"],
        "protocols": ["modbus", "modbus_tcp", "dnp3", "opc", "opc_ua", "s7comm", "unknown"]
    },
    "T0852": {
        "name": "Screen Capture",
        "tactic": "Collection",
        "asset_types": ["server", "workstation", "scada", "hmi"],
        "protocols": ["ssh", "rdp", "unknown"]
    },
    "T0853": {
        "name": "Scripting",
        "tactic": "Execution",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian",
                        "plc", "rtu", "safety_controller", "safety"],
        "protocols": ["ssh", "rdp", "http", "https", "s7comm", "unknown"]
    },
    "T0856": {
        "name": "Spoof Reporting Message",
        "tactic": "Impair Process Control",
        "asset_types": ["server", "workstation", "scada", "hmi"],
        "protocols": ["modbus", "modbus_tcp", "dnp3", "opc", "opc_ua", "s7comm", "unknown"]
    },
    "T0857": {
        "name": "System Firmware",
        "tactic": "Persistence",
        "asset_types": ["plc", "rtu", "safety_controller", "safety", "firewall", "vpn", "gateway"],
        "protocols": ["s7comm", "ssh", "rdp", "unknown"]
    },
    "T0859": {
        # Official MITRE ATT&CK for ICS: Valid Accounts applies to field controllers
        # (PLCs, RTUs, safety systems). Stuxnet and Havex both leveraged valid OT credentials.
        "name": "Valid Accounts",
        "tactic": "Lateral Movement",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian", "firewall", "vpn", "gateway",
                        "plc", "rtu", "safety_controller", "safety", "sensor", "actuator"],
        "protocols": ["ssh", "rdp", "vpn", "http", "https", "modbus", "modbus_tcp", "dnp3", "s7comm", "unknown"]
    },
    "T0866": {
        # Official MITRE ATT&CK for ICS: Remote Services applies to field controllers.
        # Industroyer (2016) used remote services to directly access RTUs/PLCs in
        # the Ukrainian power grid. This is the canonical OT lateral movement vector.
        "name": "Remote Services",
        "tactic": "Initial Access",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian", "firewall", "vpn", "gateway",
                        "plc", "rtu", "safety_controller", "safety", "sensor", "actuator"],
        "protocols": ["ssh", "rdp", "vpn", "http", "https", "modbus", "modbus_tcp", "dnp3", "s7comm", "unknown"]
    },
    "T0869": {
        # Official MITRE ATT&CK for ICS: Standard Application Layer Protocol is used
        # to communicate with field devices over standard protocols like Modbus/DNP3.
        "name": "Standard Application Layer Protocol",
        "tactic": "Command and Control",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian", "firewall", "vpn", "gateway",
                        "plc", "rtu", "safety_controller", "safety", "sensor", "actuator"],
        "protocols": ["http", "https", "ssh", "rdp", "vpn", "modbus", "modbus_tcp", "dnp3", "opc", "opc_ua", "s7comm", "unknown"]
    },
    "T0877": {
        "name": "I/O Image",
        "tactic": "Collection",
        "asset_types": ["plc", "rtu", "safety_controller", "safety", "server", "workstation", "scada", "hmi"],
        "protocols": ["modbus", "modbus_tcp", "dnp3", "opc", "opc_ua", "s7comm", "unknown"]
    },
    "T0880": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "asset_types": ["server", "workstation", "scada", "hmi", "firewall", "vpn", "gateway"],
        "protocols": ["http", "https", "ssh", "rdp", "vpn", "unknown"]
    },
    "T0881": {
        "name": "Service Stop",
        "tactic": "Inhibit Response Function",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian"],
        "protocols": ["ssh", "rdp", "unknown"]
    },
    "T0884": {
        "name": "Network Connection Enumeration",
        "tactic": "Discovery",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian"],
        "protocols": ["ssh", "rdp", "unknown"]
    },
    "T0886": {
        "name": "Modify Account",
        "tactic": "Persistence",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian", "firewall", "vpn", "gateway"],
        "protocols": ["ssh", "rdp", "vpn", "http", "https", "unknown"]
    },
    "T0887": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "asset_types": ["server", "workstation", "scada", "hmi", "historian"],
        "protocols": ["ssh", "rdp", "unknown"]
    }
}


class AttackChainReasoningAgent:
    def classify_edge_role(self, context: Dict[str, Any]) -> str:
        prev_step = context.get("previous_attack_step", "None")
        target_type = str(context.get("object_type", "")).lower()
        purdue_tgt = context.get("purdue_target", "Unknown")
        action = str(context.get("action", "")).lower()
        
        if prev_step == "None" or prev_step is None:
            if target_type in ("firewall", "vpn", "gateway"):
                return "Initial Access"
            return "Initial Access"
        
        if target_type in ("plc", "rtu", "safety_controller", "safety", "sensor", "actuator"):
            if action in ("shutdown", "stop", "restart", "device_restart"):
                return "Inhibit Response Function"
            return "Impair Process Control"
        
        if "level 1" in str(purdue_tgt).lower() or "level 0" in str(purdue_tgt).lower():
            return "Impair Process Control"
        
        if "level 2" in str(purdue_tgt).lower():
            if action in ("monitor", "read", "view"):
                return "Collection"
            return "Lateral Movement"
        
        if action in ("vpn_access", "remote_login", "ssh_access", "rdp_access", "connect"):
            return "Lateral Movement"
        
        if action in ("monitor", "read", "view", "read_diagnostics", "review_logs"):
            return "Discovery"
            
        return "Lateral Movement"


class KnowledgeBaseVerificationAgent:
    def __init__(self):
        self.kb = ATTACK_ICS_KB

    def verify(self, mapping: Dict[str, Any], context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors = []
        tech_id = str(mapping.get("technique_id", "")).upper().strip()
        tactic = str(mapping.get("tactic", "")).strip()
        name = str(mapping.get("technique_name", "")).strip()
        
        if tech_id not in self.kb:
            if re.match(r"^T\d{4}$", tech_id):
                return True, []
            else:
                errors.append(f"Knowledge Base Error: Technique ID '{tech_id}' is not in the ATT&CK for ICS catalog.")
                return False, errors
        
        kb_entry = self.kb[tech_id]
        
        if kb_entry["name"].lower() != name.lower():
            errors.append(f"Knowledge Base Error: Technique ID '{tech_id}' has name '{name}', but the official name is '{kb_entry['name']}'.")
            
        if kb_entry["tactic"].lower() != tactic.lower():
            errors.append(f"Knowledge Base Error: Technique ID '{tech_id}' has tactic '{tactic}', but the official tactic is '{kb_entry['tactic']}'.")
            
        target_type = str(context.get("object_type", "")).lower()
        if target_type and target_type != "unknown":
            if not any(asset in target_type for asset in kb_entry["asset_types"]):
                # Demote to warning only — candidate selection already filtered for asset-type
                # compatibility. If the LLM selected a candidate from the shortlist, this
                # discrepancy means the KB entry needs to be updated, not that the mapping
                # is wrong. Hard-erroring here causes the same deadlock as the action-matrix
                # double-check in SemanticValidationAgent.
                logger.debug(
                    f"[KBVerification] Note: Technique '{tech_id}' KB entry does not list "
                    f"'{target_type}' in asset_types, but it was in the candidate shortlist. "
                    f"Consider updating ATTACK_ICS_KB."
                )
                # Do NOT append to errors — this is a KB gap, not a mapping error.

        protocol = str(context.get("protocol", "")).lower()
        if protocol and protocol != "unknown":
            if not any(proto in protocol for proto in kb_entry["protocols"]) and "unknown" not in kb_entry["protocols"]:
                errors.append(f"Knowledge Base Error: Protocol '{protocol}' is not officially supported by technique '{tech_id}'.")

        return len(errors) == 0, errors


class ConfidenceCalibrationAgent:
    def __init__(self, kb=None):
        self.kb = kb or ATTACK_ICS_KB

    def calibrate(
        self,
        llm_confidence: float,
        context: Dict[str, Any],
        mapping: Dict[str, Any],
        candidates: List[Dict[str, str]],
        is_graph_consistent: bool = True
    ) -> float:
        score = float(llm_confidence) * 0.4
        
        reachable = context.get("reachability", "Yes")
        if reachable == "Yes":
            score += 0.15
        else:
            score -= 0.20
             
        firewall = context.get("firewall_status", "Allowed")
        if firewall == "Allowed":
            score += 0.15
        else:
            score -= 0.20
             
        tech_id = mapping.get("technique_id", "")
        protocol = str(context.get("protocol", "")).lower()
        if tech_id in self.kb:
            kb_entry = self.kb[tech_id]
            if any(proto in protocol for proto in kb_entry["protocols"]):
                score += 0.10
            else:
                score += 0.05
        else:
            score += 0.10
             
        target_type = str(context.get("object_type", "")).lower()
        if tech_id in self.kb:
            kb_entry = self.kb[tech_id]
            if any(asset in target_type for asset in kb_entry["asset_types"]):
                score += 0.10
            else:
                score -= 0.10
        else:
            score += 0.10
             
        if is_graph_consistent:
            score += 0.10
        else:
            score -= 0.10
             
        final_score = round(max(0.0, min(1.0, score)), 2)
         
        if firewall == "Denied":
            final_score = min(final_score, 0.40)
        if reachable == "No":
            final_score = min(final_score, 0.30)
             
        return final_score


class GraphConsistencyAgent:
    def verify_consistency(
        self,
        mapping: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        errors = []
        tactic = mapping.get("tactic", "")
        prev_tactic = context.get("previous_tactic", "Unknown")
         
        if prev_tactic != "Unknown" and prev_tactic in TACTIC_RANK and tactic in TACTIC_RANK:
            prev_rank = TACTIC_RANK[prev_tactic]
            curr_rank = TACTIC_RANK[tactic]
            if prev_rank >= 8 and curr_rank <= 2:
                errors.append(f"Graph Consistency Error: Tactic '{tactic}' (rank {curr_rank}) represents an initial stage, but follows a high-impact stage '{prev_tactic}' (rank {prev_rank}).")
                 
        return len(errors) == 0, errors


def get_candidate_techniques(context: Dict[str, Any]) -> List[Dict[str, str]]:
    return CandidateSelectionAgent().select_candidates(context)


def extract_context(
    edge: Dict[str, Any],
    edge_type: str,
    validator=None,
    ics_graph=None,
    previous_node: str = "None",
    next_node: str = "None",
) -> Dict[str, Any]:
    label = edge.get("label", {})
    source = edge.get("source", "")
    target = edge.get("target", "")

    if edge_type == "authorization":
        action = label.get("action", "access")
        protocol = "unknown"
        role_provenance = label.get("role_provenance", source)
    else:
        action = "connect"
        protocol = label.get("protocol", "unknown")
        role_provenance = "unknown"
        if ics_graph and hasattr(ics_graph, "asset_graph"):
            ag = ics_graph.asset_graph
            if ag.has_node(source):
                role_provenance = ag.nodes[source].get("role", "unknown")

    source_type = "subject"
    target_type = label.get("destination_type", "unknown")
    criticality = "medium"

    if ics_graph and hasattr(ics_graph, "asset_graph"):
        ag = ics_graph.asset_graph
        if ag.has_node(source):
            source_type = str(ag.nodes[source].get("type", source_type)).lower()
        if ag.has_node(target):
            target_type = str(ag.nodes[target].get("type", target_type)).lower()
            criticality = str(ag.nodes[target].get("criticality", "medium")).lower()

    source_zone = label.get("source_zone", "unknown")
    target_zone = label.get("target_zone", "unknown")

    firewall_allowed = True
    reachable = True
    if validator:
        if edge_type == "authorization":
            reachable = True
            firewall_allowed = True
        else:
            reachable = validator.comm_edge_exists(source, target) or validator.can_reach(source, target)
            firewall_allowed = validator.firewall_allows(
                source,
                target,
                protocol,
                src_zone=source_zone,
                tgt_zone=target_zone,
            )

    purdue_src = None
    purdue_tgt = None
    if validator:
        purdue_src = validator.get_node_purdue(source)
        purdue_tgt = validator.get_node_purdue(target)

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
        "criticality":   criticality,
        "previous_node": previous_node,
        "next_node":     next_node,
        "role_provenance": role_provenance,
    }


_SINGLE_EDGE_PROMPT = """You are an Industrial Control System security expert.

Map the following {edge_type} edge to MITRE ATT&CK for ICS.

Source Asset/Role: {source}
Source Type: {source_type}
Source Purdue Level: {purdue_source}
Source Zone: {source_zone}

Target Asset: {target}
Target Type: {target_type}
Target Purdue Level: {purdue_target}
Target Zone: {target_zone}
Target Criticality: {criticality}

Action: {action}
Protocol: {protocol}
Firewall Status: {firewall}
Reachability Status: {reachable}

Preceding Node in Chain: {previous_node}
Succeeding Node in Chain: {next_node}

Candidate Techniques to Choose From (You MUST select from this list):
{candidates_list}

Return ONLY valid JSON. No markdown, no explanation.

{{
  "technique_id": "",
  "technique_name": "",
  "tactic": "",
  "confidence": 0.0,
  "reason": ""
}}

Rules:
1. You MUST select the 'technique_id' ONLY from the list of Candidate Techniques provided above.
2. Your response MUST choose exactly ONE technique.
3. First select the technique, then generate the 'reason' justifying why this specific technique matches the context. The reason must explain the mapping in detail, referencing the asset role, protocol, and actions.
4. If the Firewall Status is Denied, the technique is UNSUCCESSFUL/ATTEMPTED. The reason MUST state that the attempt was blocked by the firewall, and the confidence score MUST be lower (maximum 0.40).
5. If the Reachability Status is No, the technique is UNSUCCESSFUL/ATTEMPTED. The reason MUST state that the target was unreachable, and the confidence score MUST be lower (maximum 0.30).
6. Tactic must match the tactic of the selected candidate technique.
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
1. You MUST select the technique_id for each edge ONLY from the Candidate Techniques listed for that specific edge.
2. For each edge, first choose the technique, then generate the 'reason' justifying why this specific technique matches the context. The reason must explain the mapping in detail, referencing the asset type, protocol, and actions.
3. If the Firewall status is Denied, or Reachable is No, the technique represents an UNSUCCESSFUL/ATTEMPTED action. The reason must mention that the attempt was blocked/unreachable, and the confidence score must be lower (maximum 0.40 for blocked, 0.30 for unreachable).
4. The tactic progression should follow a realistic attack lifecycle (Initial Access first, Impact/Impair Process Control last).
5. confidence must be a float between 0.0 and 1.0.
"""


def _extract_json(text: str) -> Any:
    if not text:
        return None

    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    for pattern in [r'\{[\s\S]*\}', r'\[[\s\S]*\]']:
        match = re.search(pattern, cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                continue

    return None


def validate_mapping(
    mapping: Dict[str, Any],
    edge_context: Dict[str, Any],
) -> Dict[str, Any]:
    builder = ContextBuilderAgent()
    enriched = builder.enrich_context(edge_context)
    
    selector = CandidateSelectionAgent()
    candidates = selector.select_candidates(enriched)
    
    semantic_agent = SemanticValidationAgent()
    sem_ok, sem_errors = semantic_agent.validate(mapping, enriched, candidates)
    
    kb_agent = KnowledgeBaseVerificationAgent()
    kb_ok, kb_errors = kb_agent.verify(mapping, enriched)
    
    graph_agent = GraphConsistencyAgent()
    graph_ok, graph_errors = graph_agent.verify_consistency(mapping, enriched)
    
    all_errors = sem_errors + kb_errors + graph_errors
    valid = (len(all_errors) == 0)
    
    tech_id = str(mapping.get("technique_id", "")).upper().strip()
    candidate_ids = {c["id"] for c in candidates}
    
    if tech_id not in candidate_ids:
        if candidates:
            mapping["technique_id"] = candidates[0]["id"]
            mapping["technique_name"] = candidates[0]["name"]
            mapping["tactic"] = candidates[0]["tactic"]
            tech_id = candidates[0]["id"]
            action = enriched.get("action", "access")
            target_type = enriched.get("object_type", "server")
            protocol = enriched.get("protocol", "unknown")
            mapping["reason"] = f"Mapped to {candidates[0]['name']} ({candidates[0]['id']}) as a deterministic fallback based on action '{action}', asset type '{target_type}', and protocol '{protocol}'."
            
    if tech_id in ATTACK_ICS_KB:
        kb_entry = ATTACK_ICS_KB[tech_id]
        mapping["technique_id"] = tech_id
        mapping["technique_name"] = kb_entry["name"]
        mapping["tactic"] = kb_entry["tactic"]
        
    firewall = enriched.get("firewall_status", "Allowed")
    reachable = enriched.get("reachability", "Yes")
    if firewall == "Denied":
        mapping["execution_status"] = "Blocked by Firewall"
    elif reachable == "No":
        mapping["execution_status"] = "Unreachable"
    else:
        mapping["execution_status"] = "Successful"
        
    calibrator = ConfidenceCalibrationAgent()
    llm_conf = mapping.get("confidence", 0.5)
    calibrated_conf = calibrator.calibrate(
        llm_conf, enriched, mapping, candidates, is_graph_consistent=graph_ok
    )
    
    mapping["validated"] = valid
    mapping["validation_warnings"] = all_errors
    mapping["adjusted_confidence"] = calibrated_conf
    
    if "evidence_trace" not in mapping:
        mapping["evidence_trace"] = {
            "action_factor": f"Action '{enriched.get('action')}' maps to target capabilities.",
            "object_type_factor": f"Target asset type is '{enriched.get('object_type')}' supporting this technique.",
            "protocol_factor": f"Protocol is '{enriched.get('protocol')}' which is relevant for the target asset.",
            "firewall_status_factor": f"Firewall permits this flow (Allowed)." if enriched.get("firewall_status") == "Allowed" else "Firewall blocked this flow (Denied).",
            "purdue_level_factor": f"Source level is {enriched.get('purdue_source')} and target level is {enriched.get('purdue_target')}."
        }
        
    return mapping


def validate_tactic_ordering(mappings: List[Dict[str, Any]]) -> Dict[str, Any]:
    tactics = [m.get("tactic", "Unknown") for m in mappings]
    violations = []

    max_rank_seen = -1
    for i, tactic in enumerate(tactics):
        rank = TACTIC_RANK.get(tactic, -1)
        if rank == -1:
            continue
        if rank < max_rank_seen:
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


def formal_analysis(
    path: List[str],
    edge_mappings: List[Dict[str, Any]],
) -> Dict[str, Any]:
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

    theta = list(set(
        tech
        for techs in mu.values()
        for tech in techs
        if tech != "Unknown"
    ))

    tactic_sequence = [m.get("tactic", "Unknown") for m in edge_mappings]
    ordering_validation = validate_tactic_ordering(edge_mappings)

    return {
        "attack_path": path,
        "mu": mu,
        "theta": sorted(theta),
        "tactic_progression": tactic_sequence,
        "ordering_validation": ordering_validation,
        "mitre_trace": mitre_trace,
    }


class LLMMITREMapper:
    def __init__(self, model: Optional[str] = None):
        self.model = model or _get_model()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._call_count = 0
        self._cache_hits = 0
        self.request_timeout_sec = float(os.getenv("OPENAI_MITRE_TIMEOUT_SEC", "25"))

    @staticmethod
    def _cache_key(context: Dict[str, Any]) -> str:
        key_fields = {
            "source":       context.get("source", ""),
            "target":       context.get("target", ""),
            "source_type":  context.get("source_type", ""),
            "target_type":  context.get("target_type", ""),
            "action":       context.get("action", ""),
            "protocol":     context.get("protocol", ""),
            "edge_type":    context.get("edge_type", ""),
            "firewall":     context.get("firewall", ""),
            "reachable":    context.get("reachable", ""),
            "source_zone":  context.get("source_zone", ""),
            "target_zone":  context.get("target_zone", ""),
            "purdue_source": context.get("purdue_source", ""),
            "purdue_target": context.get("purdue_target", ""),
        }
        raw = json.dumps(key_fields, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _call_llm(self, prompt: str, max_retries: int = 2) -> Optional[str]:
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
                    timeout=self.request_timeout_sec,
                )
                self._call_count += 1
                return response.choices[0].message.content
            except Exception as e:
                logger.warning(
                    f"[LLMMITREMapper] API call attempt {attempt+1}/{max_retries+1} failed: {e}"
                )
                if attempt < max_retries:
                    time.sleep(2 ** attempt)
                else:
                    logger.error(f"[LLMMITREMapper] All retries exhausted: {e}")
                    return None

    def map_single_edge(
        self,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        context_builder = ContextBuilderAgent()
        enriched_ctx = context_builder.enrich_context(context)

        cache_key = self._cache_key(enriched_ctx)
        if cache_key in self._cache:
            self._cache_hits += 1
            logger.debug(f"[LLMMITREMapper] Cache hit for {enriched_ctx['subject']}->{enriched_ctx['target_object']}")
            return self._cache[cache_key].copy()

        candidate_selector = CandidateSelectionAgent()
        candidates = candidate_selector.select_candidates(enriched_ctx)

        chain_agent = AttackChainReasoningAgent()
        tactic_role = chain_agent.classify_edge_role(enriched_ctx)
        enriched_ctx["classified_tactic_role"] = tactic_role

        reasoning_agent = MITREReasoningAgent(self.model, self.request_timeout_sec)
        
        semantic_agent = SemanticValidationAgent()
        kb_agent = KnowledgeBaseVerificationAgent()
        graph_agent = GraphConsistencyAgent()

        max_attempts = 3
        validation_feedback = None
        parsed = None
        raw_response = None

        for attempt in range(max_attempts):
            raw_response = reasoning_agent.generate_mapping(enriched_ctx, candidates, feedback=validation_feedback)
            if not raw_response:
                break
            
            parsed = _extract_json(raw_response)
            if not parsed or not isinstance(parsed, dict):
                validation_feedback = "Validation Error: The response is not a valid JSON object. Please return ONLY a valid JSON object matching the requested schema."
                continue
            
            sem_ok, sem_errors = semantic_agent.validate(parsed, enriched_ctx, candidates)
            kb_ok, kb_errors = kb_agent.verify(parsed, enriched_ctx)
            graph_ok, graph_errors = graph_agent.verify_consistency(parsed, enriched_ctx)
            
            all_errors = sem_errors + kb_errors + graph_errors
            if not all_errors:
                break
            else:
                validation_feedback = "Validation Failures detected:\n" + "\n".join(f"- {e}" for e in all_errors)
                logger.warning(f"[LLMMITREMapper] Validation failed on attempt {attempt+1}: {all_errors}")

        if not parsed or not isinstance(parsed, dict):
            logger.error(f"[LLMMITREMapper] Failed to obtain valid mapping after {max_attempts} attempts. Falling back.")
            parsed = self._fallback_mapping(enriched_ctx)

        validated = validate_mapping(parsed, enriched_ctx)
        validated["llm_model"] = self.model
        validated["llm_raw_response"] = raw_response[:500] if raw_response else ""

        self._cache[cache_key] = validated.copy()

        return validated

    def map_attack_path(
        self,
        path: List[str],
        edge_contexts: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        if not edge_contexts:
            return [], formal_analysis(path, [])

        edge_mappings = []
        previous_tactic = "Unknown"

        for ctx in edge_contexts:
            ctx["previous_tactic"] = previous_tactic
            mapping = self.map_single_edge(ctx)
            edge_mappings.append(mapping)
            previous_tactic = mapping.get("tactic", "Unknown")

        formal_result = formal_analysis(path, edge_mappings)

        return edge_mappings, formal_result

    @staticmethod
    def _fallback_mapping(context: Dict[str, Any]) -> Dict[str, Any]:
        target_type = context.get("target_type", "").lower()
        action = context.get("action", "").lower()
        protocol = context.get("protocol", "").lower()

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

    def get_stats(self) -> Dict[str, Any]:
        return {
            "llm_calls": self._call_count,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
            "model": self.model,
        }
