"""Investigation intelligence — root-cause clusters + cross-investigation linkage.

This package introduces a structural layer above individual findings:

  finding_type → cluster → theme → cross-investigation linkage

Everything here is deterministic. Cluster membership is a static dict; theme
emergence is a count-threshold rule; cross-investigation links are direct SQL
joins on `normalized_findings.finding_type`. No autonomous reasoning.
"""
