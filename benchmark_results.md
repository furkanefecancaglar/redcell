# REDCELL resilience benchmark

Static resilience scores for generic assistant-prompt archetypes (OWASP LLM Top 10, 18 detectors, 0 API).
Illustrative patterns, not any real company's private prompt.

| # | Archetype | Score | Grade | Findings | Top risk |
|---|-----------|------:|-------|---------:|----------|
| 1 | Hardened enterprise | 100 | Hardened | 0 | — |
| 2 | Moderately hardened | 65 | Exposed | 4 | No instruction-hierarchy / injection defense |
| 3 | Bare assistant | 43 | Vulnerable | 6 | No instruction-hierarchy / injection defense |
| 4 | Coding helper | 38 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 5 | Roleplay companion | 32 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 6 | Data analyst | 32 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 7 | RAG assistant | 23 | Vulnerable | 7 | No instruction-hierarchy / injection defense |
| 8 | Autonomous DevOps agent | 18 | Critical | 8 | No instruction-hierarchy / injection defense |
| 9 | Naive support bot | 17 | Critical | 7 | No instruction-hierarchy / injection defense |
| 10 | Tool-using ops agent | 0 | Critical | 10 | No instruction-hierarchy / injection defense |
