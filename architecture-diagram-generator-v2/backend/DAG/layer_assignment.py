import re

def _parse_purdue_to_tier(purdue_level_str):
    """Resilient parser for LLM Purdue level inconsistencies."""
    if not purdue_level_str:
        return None
        
    clean_str = str(purdue_level_str).lower()
    
    # Catch textual enterprise/corporate layers first
    if "enterprise" in clean_str or "corporate" in clean_str: return 0
    if "dmz" in clean_str: return 2
    
    # Extract numbers from "L1", "Level1", "Purdue Level 1", etc.
    match = re.search(r'(?:level|l|purdue)\s*[-_]*\s*(\d+(?:\.\d+)?)', clean_str)
    if match:
        level_num = float(match.group(1))
        # Map Level 5/4/3/2/1/0 to Tiers 0 -> 6
        mapping = {5: 0, 4: 1, 3.5: 2, 3: 3, 2: 4, 1: 5, 0: 6}
        return mapping.get(level_num, None)
        
    return None