"""Register all built-in defensive tools by importing their modules.

Add a new tool by creating a DefenseTool subclass in hexshield/tools and
importing it here; the @register decorator adds it to the registry.
"""

from . import hardening, host_inspection, intel_tools, log_analysis, runbook  # noqa: F401  (triggers @register)
