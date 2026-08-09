"""REDCELL — the security layer for AI agents.

Convenience facade so `import redcell` exposes the 0-API primitives directly:

    import redcell
    redcell.inspect("ignore all previous instructions")   # runtime firewall verdict
    redcell.analyze(system_prompt)                          # static resilience report

The individual surfaces are also importable as their own modules
(redcell_firewall, redcell_static, redcell_ci, redcell_engine, redcell_mcp, server)
and as console commands (redcell-firewall, redcell-scan, redcell-ci, redcell-mcp,
redcell-server) once installed.
"""
from redcell_firewall import inspect, guard, protect, Blocked, Verdict
from redcell_static import analyze, Report, Finding

__version__ = "1.0.0"
__all__ = ["inspect", "guard", "protect", "Blocked", "Verdict",
           "analyze", "Report", "Finding", "__version__"]
