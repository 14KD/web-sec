"""Registro central de módulos pasivos y activos de WebSec Auditor."""

from websec.modules.passive import PASSIVE_MODULES
from websec.modules.active import ACTIVE_MODULES

ALL_MODULES = PASSIVE_MODULES + ACTIVE_MODULES

MODULE_CATALOG = {cls.name: cls for cls in ALL_MODULES}

__all__ = [
    "PASSIVE_MODULES",
    "ACTIVE_MODULES",
    "ALL_MODULES",
    "MODULE_CATALOG",
]
