from typing import Optional

from .base import ModelPreConfigStep
from .preconfig_ig502 import IG502_PRECONFIG_STEP


MODEL_PRECONFIG_STEPS = [
    IG502_PRECONFIG_STEP,
]


def get_model_preconfig_step(model_name: str) -> Optional[ModelPreConfigStep]:
    for step in MODEL_PRECONFIG_STEPS:
        if step.matches(model_name):
            return step
    return None
