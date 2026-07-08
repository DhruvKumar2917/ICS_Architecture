"""
RBAC Parser — Authoritative source for subjects (S), actions (R), and permissions (E.permissions).
"""

import csv
import io
import json
import re
from typing import Any, Dict, List, Optional
from app.core.utils import slugify

def _slug(value: Any) -> str:
    return slugify(value)


def _first(*candidates) -> str:
    for c in candidates:
        if c and str(c).strip():
            return str(c).strip()
    return ""


class RBACParser:
    def __init__(self):
        self.subjects: List[Dict] = []
        self.actions:  List[Dict] = []
        self.permissions: List[Dict] = []

        self._subject_ids: set = set()
        self._action_ids:  set = set()

    def _add_subject(self, raw_id: str, raw_name: str = "", kind: str = "role") -> str:
        sid = _slug(raw_id)
        if not sid:
            return ""
        if sid not in self._subject_ids:
            self.subjects.append({
                "id":   sid,
                "name": raw_name.strip() if raw_name else raw_id.strip(),
                "kind": kind,
            })
            self._subject_ids.add(sid)
        return sid

    def _add_action(self, raw_action: str) -> str:
        name_clean = raw_action.strip()
        aid = _slug(name_clean)
        if not aid:
            return ""
        if aid not in self._action_ids:
            self.actions.append({"id": aid, "name": name_clean})
            self._action_ids.add(aid)
        return aid

    def _add_permission(
        self,
        subject_id: str,
        object_raw: str,
        action_id:  str,
        role_provenance: Optional[str] = None,
        confidence: float = 1.0,
    ):
        if not subject_id or not object_raw or not action_id:
            return
        self.permissions.append({
            "subject":          subject_id,
            "object":           _slug(object_raw),
            "action":           action_id,
            "role_provenance":  role_provenance or subject_id,
            "confidence":       confidence,
            "source":           "rbac_file",
        })

    def parse_dict(self, data: Dict) -> bool:
        if not isinstance(data, dict):
            return False

        role_entries = data.get("roles", []) + data.get("subjects", []) + data.get("users", [])
        for entry in role_entries:
            if isinstance(entry, dict):
                kind = "user" if "user" in (entry.get("type", "") or "").lower() else "role"
                role_id = _first(entry.get("id"), entry.get("name"), entry.get("role"))
                sid = self._add_subject(
                    role_id,
                    entry.get("name", role_id),
                    kind=kind,
                )
                for nested_perm in entry.get("permissions", []):
                    if not isinstance(nested_perm, dict):
                        continue
                    obj    = _first(nested_perm.get("object"), nested_perm.get("resource"),
                                    nested_perm.get("target"), nested_perm.get("asset"))
                    action = _first(nested_perm.get("action"), nested_perm.get("permission"),
                                    nested_perm.get("operation"), nested_perm.get("verb"))
                    if obj and action and sid:
                        aid = self._add_action(action)
                        self._add_permission(sid, obj, aid, role_provenance=sid)
            elif isinstance(entry, str):
                self._add_subject(entry, entry)

        for entry in data.get("actions", []):
            if isinstance(entry, str):
                self._add_action(entry)
            elif isinstance(entry, dict):
                self._add_action(_first(entry.get("id"), entry.get("name")))

        policies = data.get("policies", data.get("permissions", []))
        if not isinstance(policies, list):
            policies = []

        for p in policies:
            if not isinstance(p, dict):
                continue
            subject = _first(p.get("subject"), p.get("role"), p.get("user"), p.get("principal"))
            obj     = _first(p.get("object"), p.get("resource"), p.get("target"), p.get("asset"))
            action  = _first(p.get("action"), p.get("permission"), p.get("operation"), p.get("verb"))
            role_pv = _first(p.get("role"), subject)

            if subject and obj and action:
                sid = self._add_subject(subject, subject)
                aid = self._add_action(action)
                self._add_permission(sid, obj, aid, role_provenance=_slug(role_pv))

        return bool(self.subjects or self.permissions)

    def parse_json(self, content: str) -> bool:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return False
        return self.parse_dict(data)

    def parse_yaml(self, content: str) -> bool:
        data = None
        try:
            import yaml
            data = yaml.safe_load(content)
        except Exception:
            data = self._parse_yaml_regex_fallback(content)

        if not data:
            return False

        if isinstance(data, list):
            data = {"roles": data}
        elif not isinstance(data, dict):
            return False

        return self.parse_dict(data)

    def _parse_yaml_regex_fallback(self, content: str) -> Optional[Dict]:
        roles_list = []
        blocks = re.split(r'\n-\s+', '\n' + content)
        
        for block in blocks:
            if not block.strip():
                continue
            
            role_name = None
            perms = []
            curr_action = None
            curr_object = None
            
            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                m_role = re.search(r'\brole:\s*[\'"]?([\w_\-]+)[\'"]?', line)
                if m_role:
                    role_name = m_role.group(1)
                    continue
                
                m_action = re.search(r'\baction:\s*[\'"]?([\w_\-]+)[\'"]?', line)
                if m_action:
                    if curr_action and curr_object:
                        perms.append({"action": curr_action, "object": curr_object})
                        curr_action, curr_object = None, None
                    curr_action = m_action.group(1)
                
                m_object = re.search(r'\bobject:\s*[\'"]?([\w_\-]+)[\'"]?', line)
                if m_object:
                    curr_object = m_object.group(1)
                    if curr_action and curr_object:
                        perms.append({"action": curr_action, "object": curr_object})
                        curr_action, curr_object = None, None

            if curr_action and curr_object:
                perms.append({"action": curr_action, "object": curr_object})
                
            if role_name:
                roles_list.append({
                    "role": role_name,
                    "permissions": perms
                })
                
        return {"roles": roles_list} if roles_list else None

    def parse_csv(self, content: str) -> bool:
        try:
            reader = csv.DictReader(io.StringIO(content))
            parsed = False
            for row in reader:
                r = {k.strip().lower(): v.strip() for k, v in row.items() if k}

                subject  = _first(r.get("subject"), r.get("role"), r.get("user"), r.get("principal"))
                obj      = _first(r.get("object"), r.get("resource"), r.get("target"), r.get("asset"))
                action   = _first(r.get("action"), r.get("permission"), r.get("operation"), r.get("verb"))
                role_pv  = _first(r.get("role_name"), r.get("role"), subject)

                if subject and obj and action:
                    sid = self._add_subject(subject, subject)
                    aid = self._add_action(action)
                    self._add_permission(sid, obj, aid, role_provenance=_slug(role_pv))
                    parsed = True
            return parsed
        except Exception:
            return False

    def parse_casbin(self, content: str) -> bool:
        parsed = False
        role_map: Dict[str, str] = {}

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]

            if parts[0] in ("p", "p2") and len(parts) >= 4:
                subject, obj, action = parts[1], parts[2], parts[3]
                sid = self._add_subject(subject, subject, kind="role")
                aid = self._add_action(action)
                self._add_permission(sid, obj, aid, role_provenance=sid)
                parsed = True

            elif parts[0] == "g" and len(parts) >= 3:
                user, role = parts[1], parts[2]
                user_slug = _slug(user)
                role_slug = _slug(role)
                role_map[user_slug] = role_slug
                self._add_subject(user, user, kind="user")
                self._add_subject(role, role, kind="role")

        for perm in self.permissions:
            if perm["subject"] in role_map:
                perm["role_provenance"] = role_map[perm["subject"]]

        return parsed

    def parse_plaintext(self, content: str) -> bool:
        parsed = False

        pA = re.compile(
            r"(?:allow|permit|grant)\s+([\w\-]+)\s+to\s+([\w_\-]+)\s+(?:on\s+|at\s+|to\s+)?([\w_\-]+)",
            re.IGNORECASE,
        )
        pB = re.compile(
            r"([\w\-]+)\s+(?:can|may|has|is\s+allowed\s+to|is\s+permitted\s+to)\s+([\w_\-]+)\s+(?:to\s+|on\s+)?([\w_\-]+)",
            re.IGNORECASE,
        )
        pC = re.compile(
            r"^([\w\-]+)\s*:\s*([\w_\-]+)\s+([\w_\-]+)$",
            re.IGNORECASE,
        )
        pD = re.compile(
            r"^([\w\-]+)\s{2,}([\w_\-]+)\s{2,}([\w_\-]+)\s*$",
            re.IGNORECASE,
        )

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for pattern in (pA, pB, pC, pD):
                m = pattern.search(line)
                if m:
                    g = m.groups()
                    subject, action, obj = (g[0], g[1], g[2]) if len(g) == 3 else ("", "", "")
                    if subject and action and obj and obj.lower() != action.lower():
                        sid = self._add_subject(subject, subject)
                        aid = self._add_action(action)
                        self._add_permission(sid, obj, aid, role_provenance=sid)
                        parsed = True
                    break

        known = re.findall(
            r"\b(VendorMaint|OEMOps|WFTech|NetAdmin|OEMAdmin|CustomerOps"
            r"|FieldEngineer|SiteOperator|Vendor[A-Za-z]\w*|OEM[A-Za-z]\w*|WF[A-Za-z]\w*|Net[A-Za-z]\w*)\b",
            content,
            re.IGNORECASE,
        )
        exclude_keywords = {"firewall", "gw", "gateway", "server", "host", "plc", "hmi", "switch", "router", "sensor", "actuator", "device"}
        for role in set(known):
            role_lower = role.lower()
            if any(kw in role_lower for kw in exclude_keywords):
                continue
            self._add_subject(role, role, kind="role")
            parsed = True

        return parsed

    def parse(self, content: str) -> "RBACParser":
        if not content or not content.strip():
            print("  [rbac_parser] WARNING: empty content - nothing to parse", flush=True)
            return self

        content = content.strip()
        fmt = "unknown"

        if content.startswith("{") or content.startswith("["):
            if self.parse_json(content):
                fmt = "json"

        if not self.subjects and ("roles:" in content or "permissions:" in content or re.search(r'^\s*-\s+\w+:', content)):
            if self.parse_yaml(content):
                fmt = "yaml"

        if not self.subjects and re.search(r"^\s*[pg]\s*,", content, re.MULTILINE):
            if self.parse_casbin(content):
                fmt = "casbin"

        if not self.subjects and "," in content and "\n" in content:
            if self.parse_csv(content):
                fmt = "csv"

        if not self.subjects:
            self.parse_plaintext(content)
            fmt = "plaintext"

        print(f"  [rbac_parser] Format detected: {fmt}", flush=True)
        print(f"  [rbac_parser] Extracted:", flush=True)
        print(f"    S (subjects)  = {[s['id'] for s in self.subjects]}", flush=True)
        print(f"    R (actions)   = {[a['id'] for a in self.actions]}", flush=True)
        print(f"    permissions   = {len(self.permissions)}", flush=True)
        return self

    def to_dict(self) -> Dict:
        return {
            "S":           self.subjects,
            "R":           self.actions,
            "permissions": self.permissions,
        }


def parse_rbac(content: str) -> Dict:
    return RBACParser().parse(content).to_dict()
