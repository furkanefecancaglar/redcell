# Security policy

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button on the Security tab, which
opens a private advisory only the maintainers can see. Please do not open a public issue for
anything exploitable.

Useful things to include: what you sent, what came back, and why it matters. A curl command that
reproduces it is worth more than a paragraph describing it.

You will get a first response within 72 hours. If a fix is warranted it ships to
https://redcell.redcellv1.workers.dev and the advisory is published afterwards, crediting you
unless you would rather stay anonymous.

## Scope

In scope: the deployed Worker at `redcell.redcellv1.workers.dev`, the engines in this repository,
and the vendorable files served from `/src/`.

Out of scope: findings that only demonstrate the documented limits below, denial of service
through volume, and anything requiring access to a maintainer's machine or accounts.

## What this product does NOT claim

Detection limits are measured and published rather than implied, because a security tool that
oversells itself is a liability to the people who trust it.

- The engines are deterministic pattern matchers. They catch known shapes of attack and **miss
  roughly a third of novel phrasings** — measured on a held-out set nobody tuned against: 0
  false positives on 30 ordinary business messages, 7 of 20 adversarial prompts missed. The families they
  miss are social-engineering framing, payloads hidden inside documents the agent was asked to
  process, and encodings outside the normalisers. See `/methodology`.
- Non-English coverage is Turkish, Spanish, German and French. Attacks in other languages are
  **not** detected, and that is asserted in the test suite so it cannot become an accidental claim.
- A high prompt score means known weaknesses are absent. It is not proof an agent is safe.
- The live adversarial engine is not reproducible: the same prompt has scored 49 to 80. The
  report ships that spread alongside the number.

A finding that the tool misses one of these documented classes is a known limit, not a
vulnerability. A finding that it can be made to **pass something it claims to block**, or that
the service leaks or accepts forged authority, very much is.

## Handling of user data

Prompts and inputs sent to the analysis endpoints are not stored. Scan history stores finding
metadata — rule id, title, severity, score — never the text that produced it. See `/privacy`.
