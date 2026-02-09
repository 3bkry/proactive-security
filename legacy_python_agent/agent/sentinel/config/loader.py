from pathlib import Path
from typing import Optional, Dict, Any
import yaml
from pydantic import ValidationError

from .schema import SentinelConfig
from .defaults import DEFAULT_CONFIG_PATH

class ConfigLoader:
    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path

    def load(self) -> SentinelConfig:
        """
        Load configuration from YAML file, validation with Pydantic schema.
        Returns default config if file does not exist.
        """
        if not self.config_path.exists():
            return SentinelConfig()

        try:
            with open(self.config_path, "r") as f:
                raw_config = yaml.safe_load(f) or {}
            
            # Pydantic handles validation and default values
            return SentinelConfig(**raw_config)
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing config file: {e}")
        except ValidationError as e:
            raise ValueError(f"Invalid configuration: {e}")

def load_config(path: Optional[Path] = None) -> SentinelConfig:
    """Helper function to load config from a specific path or default."""
    loader = ConfigLoader(path or DEFAULT_CONFIG_PATH)
    return loader.load()
