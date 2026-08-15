# REDCELL resilience benchmark

Static resilience scores for generic assistant-prompt archetypes (OWASP LLM Top 10, 22 detectors, 0 API).
Illustrative patterns, not any real company's private prompt.

| # | Archetype | Score | Grade | Findings | Top risk |
|---|-----------|------:|-------|---------:|----------|
| 1 | Hardened enterprise | 100 | Hardened | 0 | — |
| 2 | Moderately hardened | 65 | Exposed | 4 | No instruction-hierarchy / injection defense |
| 3 | HR records agent | 48 | Exposed | 5 | No instruction-hierarchy / injection defense |
| 4 | Bare assistant | 43 | Vulnerable | 6 | No instruction-hierarchy / injection defense |
| 5 | Finance reconciler | 39 | Vulnerable | 5 | No instruction-hierarchy / injection defense |
| 6 | Coding helper | 38 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 7 | Medical triage bot | 37 | Vulnerable | 6 | No instruction-hierarchy / injection defense |
| 8 | Roleplay companion | 32 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 9 | Data analyst | 32 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 10 | Travel booking agent | 32 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 11 | Code reviewer bot | 28 | Vulnerable | 6 | No instruction-hierarchy / injection defense |
| 12 | RAG assistant | 23 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 13 | Autonomous DevOps agent | 18 | Critical | 8 | No instruction-hierarchy / injection defense |
| 14 | Legal research assistant | 18 | Critical | 8 | No instruction-hierarchy / injection defense |
| 15 | Naive support bot | 17 | Critical | 7 | No instruction-hierarchy / injection defense |
| 16 | Tool-using ops agent | 0 | Critical | 10 | No instruction-hierarchy / injection defense |
