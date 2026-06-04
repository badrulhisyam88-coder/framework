from apps.investigation_core.skills.taxonomy.auth_skills import AUTH_SKILLS
from apps.investigation_core.skills.taxonomy.hardening_skills import HARDENING_SKILLS
from apps.investigation_core.skills.taxonomy.sqli_skills import SQLI_SKILLS
from apps.investigation_core.skills.taxonomy.xss_skills import XSS_SKILLS

ALL_SKILLS = [*SQLI_SKILLS, *XSS_SKILLS, *AUTH_SKILLS, *HARDENING_SKILLS]

__all__ = [
    "SQLI_SKILLS", "XSS_SKILLS", "AUTH_SKILLS",
    "HARDENING_SKILLS", "ALL_SKILLS",
]
