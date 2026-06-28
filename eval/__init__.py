"""VeriAudit evaluation harness.

Runs the worker pipeline against a labeled benchmark set and reports per-class
precision / recall / false-positive rate, exploit-confirmation rate, and a
basic explanation-quality score.

Honesty rule (CLAUDE.md): the "clean" reference set is labeled "no known
labeled vulnerabilities in the benchmark context," NOT "safe."
"""

__version__ = "0.1.0"
