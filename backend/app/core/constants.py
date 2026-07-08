from typing import List, Dict

# Canonical Tactic Ordering ρ for MITRE ATT&CK for ICS
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
