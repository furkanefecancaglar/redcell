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

- The engines are deterministic pattern matchers. Against attack families nobody tuned for they
  catch **roughly half**. That is now measured twice, on two sets written to share nothing with
  each other or with anything in the repo, each measured once and then retired:
  - Set A: 13 of 25 adversarial prompts missed (48% detection), 2 false positives on 41 ordinary messages.
  - Set B: 12 of 26 adversarial prompts missed (54% detection), 0 false positives on 36 ordinary messages.

  Two independent sets landing in the same place is a firmer number than either alone. Set A's
  families — markdown-URL exfiltration, memory poisoning, fiction framing, constrained-answer
  refusal suppression, percent/entity encoding, non-English tool coercion — were closed against a
  separate training set, which is why set A is retired rather than re-quoted. **What set B shows
  we still miss:** instructions addressed to a downstream agent, a JSON field named for the secret
  the model is asked to fill in, conditional and deferred triggers ("once this conversation
  exceeds three messages"), directives laundered through a citation, and full-width unicode.
  Those are published rather than fixed quietly, because a set you repair against stops measuring
  anything. See `/methodology`.
- An **optional** second stage (`classifier: true`, off by default) adds a 3,000-weight logistic
  regression trained on the public training splits — 47 KB in the bundle, no API call, no key.
  It takes third-party recall from 28% to 91% on safe-guard at 98% precision, moves deepset from
  17% to 18%, and adds **nothing** on our own independent set: it learned those corpora's
  distribution, not the general problem. It can only escalate allow→flag and never blocks, since
  a component that cannot explain its verdict should not hard-stop traffic. Reproduce with
  `python tools/thirdparty_bench.py`.
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
