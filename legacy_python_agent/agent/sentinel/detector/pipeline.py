from typing import Dict, List, Optional
import time

from ..parser.base import LogParser, ParsedEvent
from ..parser.nginx import NginxParser
from ..parser.ssh import SSHParser
from ..parser.generic import GenericParser
from .rules.engine import RuleEngine
from ..store.models import Threat
from ..config.schema import DetectionConfig
from ..utils.logging import get_logger

logger = get_logger("detection_pipeline")

class DetectionPipeline:
    def __init__(self, config: DetectionConfig):
        self.config = config
        self.parsers: Dict[str, LogParser] = {
            "nginx": NginxParser(),
            "ssh": SSHParser(),
            "generic": GenericParser(),
        }
        self.rule_engine = RuleEngine(config.rules_path)
        self.rule_engine.load_rules()

    async def analyze(self, source_path: str, log_line: str) -> Optional[Threat]:
        """
        Process a raw log line through the detection pipeline.
        1. Identify parser based on source path/type
        2. Parse event
        3. Check against rules
        4. (Future) Check anomalies
        5. (Future) LLM check
        """
        parser = self._get_parser(source_path)
        if not parser:
            return None

        try:
            event = parser.parse(log_line, time.time())
            if not event:
                return None
                
            # Stage 1: Rule Engine
            threat = self.rule_engine.evaluate(event)
            if threat:
                return threat
                
            # Stage 2: Anomaly Detection (TODO)
            
            # Stage 3: LLM (TODO)
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing line from {source_path}: {e}")
            return None

    def _get_parser(self, path: str) -> Optional[LogParser]:
        # Simple heuristic mapping for now
        if "nginx" in path:
            return self.parsers["nginx"]
        if "auth.log" in path or "secure" in path:
            return self.parsers["ssh"]
        return self.parsers["generic"]
