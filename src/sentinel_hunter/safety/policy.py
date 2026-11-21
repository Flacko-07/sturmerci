import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class SafetyPolicy:
    profile_name: str
    max_concurrent_requests: int = 50
    rate_limit_per_second: int = 10
    enable_netns_isolation: bool = False
    require_approval: bool = False
    max_scan_duration_minutes: int = 60
    log_level: str = "info"
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)

def load_profile(profile_name: str) -> SafetyPolicy:
    profile_dir = Path(__file__).parent / "profiles"
    profile_path = profile_dir / f"{profile_name}.yaml"
    if not profile_path.exists():
        raise ValueError(f"Safety profile '{profile_name}' not found.")
    with open(profile_path, "r") as f:
        data = yaml.safe_load(f)
    return SafetyPolicy(**data)
