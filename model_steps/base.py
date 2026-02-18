from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple


@dataclass(frozen=True)
class ModelPreConfigStep:
    """Pluggable model-specific pre-config step metadata + executor."""

    key: str
    display_name: str
    model_matcher: Callable[[str], bool]
    executor: Callable[[Dict, Dict], Tuple[bool, str, Optional[str]]]

    def matches(self, model_name: str) -> bool:
        return self.model_matcher(str(model_name or ""))
