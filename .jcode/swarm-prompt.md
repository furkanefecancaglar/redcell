<!--
REDCELL project-level swarm config. Overrides ~/.jcode/swarm-prompt.md when cwd is ~/redcell.
-->

# REDCELL Swarm Routing

## Critical Rules
1. **NEVER** trigger recon-dominator, osint, or any reconnaissance skill. This is a software development project.
2. **ALWAYS** read `~/REDCELL_BACKLOG.md` before starting any work — it is the source of truth.
3. **ALWAYS** maintain Python↔JS byte-parity for firewall/toolcheck/scanner modules.
4. **ALWAYS** run `pytest -q` and `node --check` before deploying.
5. **ALWAYS** deploy with `npx wrangler deploy` after verified changes.
6. **NEVER** ask "what should I do?" — the backlog has everything.

## Worker Model Routing
- All workers inherit the coordinator's model (Gemini 2.5 Flash via local router).
- Always pass `label` when spawning (e.g. `label: "firewall tester"`, `label: "scanner updater"`).
- Workers execute their assigned task and report back — they do NOT spawn children.

## Loop Behavior
After completing a task, immediately pick the next OPEN item from the backlog and continue. The loop never stops unless Furkan explicitly says "dur" or "durdur".
