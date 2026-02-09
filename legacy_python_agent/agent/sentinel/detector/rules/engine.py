import re
import yaml
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass

from ...parser.base import ParsedEvent
from ...store.models import Threat
from ...utils.logging import get_logger

logger = get_logger("rule_engine")

@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    source: str
    patterns: List[re.Pattern]
    threshold: int
    window: int
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Rule':
        patterns = []
        for cond in data.get("conditions", []):
            if "pattern" in cond:
                try:
                    patterns.append(re.compile(cond["pattern"]))
                except re.error as e:
                    logger.error(f"Invalid regex for rule {data.get('id')}: {e}")
        
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            severity=data.get("severity", "MEDIUM"),
            source=data.get("log_source", "any"),
            patterns=patterns,
            threshold=data.get("aggregation", {}).get("threshold", 1),
            window=data.get("aggregation", {}).get("window", 60),
        )

class RuleEngine:
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self.rules: List[Rule] = []
        self.state: Dict[str, List[float]] = {} # Sliding window state (ip -> [timestamps])

    def load_rules(self):
        """Load YAML rules from directory."""
        if not self.rules_path.exists():
            return
            
        for rule_file in self.rules_path.glob("*.yml"):
            try:
                with open(rule_file, "r") as f:
                    data = yaml.safe_load(f)
                    rule = Rule.from_dict(data)
                    self.rules.append(rule)
            except Exception as e:
                logger.error(f"Failed to load rule {rule_file}: {e}")

    def evaluate(self, event: ParsedEvent) -> Optional[Threat]:
        """
        Evaluate event against rules.
        Returns a Threat if a rule triggers, else None.
        Limitation: Only checks basic pattern match for now.
        Aggregation is complex to implement in a stateless call, 
        will implement basic immediate Match.
        """
        for rule in self.rules:
            if rule.source != "any" and rule.source != event.source:
                continue
                
            for pattern in rule.patterns:
                match = pattern.search(event.raw)
                if match:
                    # For MVP, we skip aggregation and return threat immediately
                    # Real implementation needs a stateful aggregator
                    logger.info(f"Rule match: {rule.name} on {event.raw}")
                    
                    groups = match.groupdict()
                    attacker_ip = groups.get("attacker_ip") or groups.get("ip") or event.data.get("ip") or event.data.get("remote_addr")
                    
                    return Threat(
                        source=event.source,
                        severity=rule.severity,
                        type="rule_match",
                        description=rule.description,
                        attacker_ip=attacker_ip,
                        raw_log=event.raw,
                        risk_score=0.8, # hardcoded for now
                        rule_id=rule.id,
                        status="open"
                    )
        return None
