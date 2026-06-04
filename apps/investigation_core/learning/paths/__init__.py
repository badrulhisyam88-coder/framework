from apps.investigation_core.learning.paths.auth_beginner import AUTH_BEGINNER
from apps.investigation_core.learning.paths.sqli_beginner import SQLI_BEGINNER
from apps.investigation_core.learning.paths.sqli_intermediate import SQLI_INTERMEDIATE
from apps.investigation_core.learning.paths.web_hardening_beginner import WEB_HARDENING_BEGINNER
from apps.investigation_core.learning.paths.xss_beginner import XSS_BEGINNER
from apps.investigation_core.learning.paths.xss_intermediate import XSS_INTERMEDIATE

ALL_PATHS = [
    SQLI_BEGINNER, SQLI_INTERMEDIATE,
    XSS_BEGINNER, XSS_INTERMEDIATE,
    AUTH_BEGINNER,
    WEB_HARDENING_BEGINNER,
]

__all__ = [
    "SQLI_BEGINNER", "SQLI_INTERMEDIATE",
    "XSS_BEGINNER", "XSS_INTERMEDIATE",
    "AUTH_BEGINNER",
    "WEB_HARDENING_BEGINNER",
    "ALL_PATHS",
]
