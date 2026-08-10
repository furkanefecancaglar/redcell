/*!
 * REDCELL static scanner — JS port of redcell_static.py (22 OWASP LLM detectors).
 * Zero deps, browser + Node. Regexes use ONLY the 'i' flag (= Python re.IGNORECASE,
 * NO dotAll) so scores match the Python core exactly (weak 17 / agent 0 / hard 90).
 *
 *   const { analyze } = require('./redcell_scanner.js');
 *   analyze(systemPrompt) -> { score, grade, has_critical, passed, findings:[...] }
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.REDCELL_SCANNER = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const SEV_W = { crit: 34, high: 20, med: 11, low: 5 };
  const HIDDEN = /[​-‏‪-‮⁠-⁤﻿­]/;
  const R = String.raw;

  // [owasp, cat, sev, title, kind, a, b] — kind: absent|present|cond|len|hidden
  const DET = [
    ['LLM01', 'Prompt injection', 'high', 'No instruction-hierarchy / injection defense', 'absent',
      R`(ignore (any|all)?\s*(previous|prior|earlier|user)?\s*(instructions|commands)|do not follow (any )?(instructions|commands) (in|from)|treat (all )?.{0,30}(as (untrusted|data)|not as instructions)|these instructions (cannot|can'?t|may not) be (overridden|changed|ignored)|regardless of (what|any)|even if (the )?user (asks|says|instructs)|user (input|content) is (untrusted|data))`, null],
    ['LLM07', 'System-prompt leakage', 'med', 'System prompt not marked confidential', 'absent',
      R`(do not (reveal|share|disclose|repeat|print|output|expose)|never (reveal|share|disclose|repeat|print)|keep .{0,20}(confidential|secret|private)|(system )?(prompt|instructions) (are|is) confidential|will not (share|reveal))`, null],
    ['LLM01', 'Jailbreak surface', 'med', 'No explicit refusal boundaries', 'absent',
      R`(refuse|decline|do not (provide|assist|help|answer|comply|generate)|you (must|should|will) not|never (provide|generate|assist|help)|not allowed to|off[- ]?limits|out of scope)`, null],
    ['LLM01', 'Persona override', 'low', 'No role-lock against persona hijacking', 'absent',
      R`(stay in (character|role)|remain (a|an|the) .{0,20}(assistant|agent)|do not (adopt|assume|pretend|roleplay|role-play|impersonate|become)|do not change your (role|persona|identity)|you are always)`, null],
    ['LLM06', 'Excessive agency', 'high', 'High-impact tools without guardrails', 'cond',
      R`\b(delete|drop table|transfer (funds|money)|send (an? )?(email|message|dm)|make (a )?payment|issue (a )?refund|purchase|buy|execute (code|command|shell|sql)|run (a )?(command|shell|sql|script)|wire|deploy|sudo|charge|revoke|grant access)\b`,
      R`(confirm|require (approval|authorization|confirmation)|human[- ]in[- ]the[- ]loop|only if|must (verify|check)|read[- ]only|do not (delete|send|transfer|execute)|ask (the user |for )?(before|permission)|never (perform|execute|send) .{0,30}without)`],
    ['LLM06', 'Over-trust', 'high', 'Blanket trust / authority delegation', 'present',
      R`(do whatever (the )?user (says|asks|wants|requests)|the user is (an? )?(admin|administrator|developer|authori[sz]ed|trusted|staff)|always (comply|obey|do as)|no (restrictions|limitations|filters?|rules)|without (any )?(restriction|limitation|refusal|question)|trust (the user|everything))`, null],
    ['LLM02', 'Secret exposure', 'crit', 'Hardcoded secret in the prompt', 'present',
      R`(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(api[_-]?key|secret|token|password|passwd|bearer)\s*[:=]\s*['"]?[A-Za-z0-9_\-\.]{10,})`, null],
    ['LLM05', 'Insecure output handling', 'med', 'Model output rendered/executed without sanitization', 'cond',
      R`((render|display|output|return|embed|inject) .{0,30}(html|markdown|iframe|image|link|script)|execute .{0,20}(the )?(code|output|response)|eval\(|innerhtml|dangerouslysetinnerhtml)`,
      R`(saniti[sz]e|escape|encode|strip|do not render|plain text only|no (html|scripts?))`],
    ['LLM02', 'Sensitive data access', 'med', 'Access to sensitive data without handling rules', 'cond',
      R`\b(social security|ssn|credit card|card number|passport|medical record|health record|patient|customer (data|records|pii|accounts?)|account (balance|number)|inbox|emails?|private (data|messages?)|database of (users|customers))\b`,
      R`(do not (share|expose|reveal|log)|redact|mask|minimi[sz]e|only .{0,20}(necessary|relevant)|need[- ]to[- ]know|never (include|repeat) .{0,20}(pii|sensitive|personal))`],
    ['LLM09', 'Specification', 'low', 'Underspecified prompt', 'len', null, null],
    ['LLM01', 'Retrieval provenance', 'high', 'Retrieved/RAG content lacks provenance rules', 'cond',
      R`\b(retriev\w+|rag\b|knowledge base|vector (store|db|database)|search results?|documents? (you|it) (read|retrieve|process)|context (provided|from) (documents|search)|web (page|search) results?)\b`,
      R`(untrusted|provenance|do not (follow|obey|execute) .{0,30}(instructions|commands) (in|from) .{0,20}(document|content|retriev|source)|treat .{0,25}(retriev|document|content|search) .{0,12}as data|is (not )?(an )?instruction)`],
    ['LLM01', 'Indirect injection', 'high', 'Tool/function output not treated as untrusted', 'cond',
      R`\b(tool (result|output|response)|function (result|output|call)|api (response|result|output)|the (result|output|response) (of|from) (a|the|your|each) (tool|function|api|call)|tool_result|plugin (output|result|response)|results? returned (by|from) (a |the )?(tool|function|api|plugin)|when (a |the )?tool returns)\b`,
      R`\b(tool|function|api|plugin) (output|result|response)s?\b[^.]{0,60}(untrusted|as data|not (an? )?instruction|never (an? )?instruction)|treat[^.]{0,60}(as (untrusted|data)|never as instructions?|not as instructions?)|do not (follow|obey|execute|trust|act on)[^.]{0,45}(tool|function|api|plugin|result|output|response)|(tool|function|api|plugin) (output|result|response)s? (are|is) (untrusted|data|not )`],
    ['LLM01', 'Hidden-character smuggling', 'high', 'Invisible / bidi control characters in prompt', 'hidden', null, null],
    ['LLM06', 'Unsupervised autonomy', 'high', 'Autonomous action without human oversight', 'cond',
      R`\b(autonomous(ly)?|without (asking|confirming|human|approval)|on your own|take initiative|act independently|decide and (execute|act|do)|complete the (whole )?task .{0,15}(yourself|without)|fully automated)\b`,
      R`(confirm|human[- ]in[- ]the[- ]loop|ask (for )?(approval|permission)|require .{0,15}(approval|confirmation)|check with .{0,10}(a )?human|escalate to .{0,10}human)`],
    ['LLM07', 'Tool-schema exposure', 'med', 'Tool/function schema embedded in the prompt', 'present',
      R`("parameters"\s*:|"type"\s*:\s*"(object|function|string)"|function (signature|schema|definition)|\bdef \w+\s*\(|"arguments"\s*:|json ?schema|tool[s]? (spec|schema|definition))`, null],
    ['LLM01', 'Memory poisoning', 'med', 'Persistent memory without validation', 'cond',
      R`\b(remember|memor(y|ize)|save (this|the|user|what)|store (this|the|user|what)|persist|recall (later|across)|long[- ]term memory|note (this )?for later)\b`,
      R`(verif|validat|(never|do not|don'?t) (store|save|remember|keep|log) .{0,25}(sensitive|secret|pii|credential|privilege|personal|admin)|only .{0,25}(necessary|relevant|task-)|minimi[sz]e|sanit)`],
    ['LLM02', 'Sensitive logging', 'med', 'Logs or echoes raw input without redaction', 'cond',
      R`\b(log|record|echo|repeat back|store) .{0,25}(the )?(user|input|request|message|conversation|prompt)s?\b`,
      R`(redact|mask|do not (log|store|record) .{0,20}(sensitive|secret|pii|password|credential)|sanit|strip .{0,15}(sensitive|secret))`],
    ['LLM10', 'Unbounded consumption', 'low', 'No output-length or loop limits', 'cond',
      R`\b(agent|tool|loop|iterate|for each|generate|write|draft|compose|browse|search|crawl|multi[- ]step|until (done|complete)|repeat(edly)?|keep going)\b`,
      R`(be (concise|brief)|keep .{0,20}(it )?(short|brief|concise)|word (limit|count)|no more than|at most \d|limit (your|the) (response|output|answer)|do not (loop|repeat)|max(imum)? (length|tokens?|steps?)|stop after|one (tool )?round)`],
    ['LLM09', 'Misinformation', 'low', 'No uncertainty / anti-fabrication rule', 'absent',
      R`(do not (make up|fabricate|invent|hallucinate|guess)|if (you (are )?(unsure|uncertain)|you don'?t know)|say (you )?(don'?t know|are unsure)|cite (your )?sources?|only .{0,15}(verified|factual|accurate)|admit (uncertainty|when)|avoid speculation|don'?t speculate)`, null],
    ['LLM06', 'Over-broad access', 'high', 'Over-broad tool or permission grant', 'present',
      R`\b(full access|all tools?|any (tool|api|action|command|system call)|unrestricted access|admin (rights|privileges|access|mode)|root access|complete control|do (absolutely )?anything (the user|they) (want|ask|say))\b`, null],
    ['LLM09', 'Output format', 'low', 'No output-format / schema constraint for machine-consumed output', 'cond',
      R`\b(return|output|respond with|produce|emit|send)\b.{0,30}\b(json|xml|data|results?|payload|response) (to|for|into|that) (the )?(api|system|caller|frontend|database|another|downstream|parser|service)\b|\bthe (output|response|result) (is|will be) (parsed|consumed|used) by\b`,
      R`\b(valid json|json ?schema|respond (only )?(in|with) (json|structured)|follow (this|the) (format|schema)|structured output|only (return|output)|output (format|schema)|must be valid json)\b`],
    ['LLM02', 'Identity binding', 'med', 'Privilege derived from conversation, not a verified session', 'cond',
      R`\b((grant|give|check|verify|determine|treat as|assume) .{0,20}(admin|privileg\w+|elevated access|permission)|user'?s? (privileg\w+|admin|role|permission|access level)|(is|are) (the user |they )?(an? )?admin\b)`,
      R`\b(authenticated session|verified (session|identity)|backend (provides|passes|supplies)|out[- ]of[- ]band|session (token|claim)|do not (derive|infer|grant|trust) .{0,30}(from )?(the )?(conversation|user (message|claim|input|says)))\b`],
  ].map(([owasp, cat, sev, title, kind, a, b]) => ({
    owasp, cat, sev, title, kind,
    a: a ? new RegExp(a, 'i') : null,
    b: b ? new RegExp(b, 'i') : null,
  }));

  const ORDER = { crit: 0, high: 1, med: 2, low: 3 };

  function hit(re, text) { const m = re.exec(text); return m ? m[0] : null; }

  function analyze(text) {
    text = text || '';
    const findings = [];
    let passed = 0;
    for (const d of DET) {
      let weak = false, ev = '';
      if (d.kind === 'absent') {
        const h = hit(d.a, text);
        weak = h === null;
        ev = h === null ? '' : 'defense present: "' + h.slice(0, 60) + '"';
      } else if (d.kind === 'present') {
        const h = hit(d.a, text);
        weak = h !== null;
        ev = h ? 'risky pattern: "' + h.slice(0, 50) + '"' : '';
      } else if (d.kind === 'cond') {
        const trig = hit(d.a, text);
        const guarded = d.b.test(text);
        weak = !!trig && !guarded;
        ev = trig ? 'surface: "' + trig.slice(0, 50) + '"' + (guarded ? ' (guarded)' : '') : '';
      } else if (d.kind === 'len') {
        const n = text.trim().length;
        weak = n > 0 && n < 220;
        ev = n + ' chars';
      } else if (d.kind === 'hidden') {
        const m = HIDDEN.exec(text);
        weak = m !== null;
        ev = m ? 'U+' + m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0') : '';
      }
      if (weak) findings.push({ id: d.owasp, cat: d.cat, sev: d.sev, title: d.title, evidence: ev });
      else passed++;
    }
    const penalty = findings.reduce((s, f) => s + SEV_W[f.sev], 0);
    const score = Math.max(0, Math.min(100, 100 - penalty));
    const grade = score >= 85 ? 'Hardened' : score >= 70 ? 'Resilient' : score >= 45 ? 'Exposed'
      : score >= 20 ? 'Vulnerable' : 'Critical';
    findings.sort((x, y) => ORDER[x.sev] - ORDER[y.sev]);
    return { score, grade, passed, has_critical: findings.some(f => f.sev === 'crit'), findings };
  }

  return { analyze, DET };
});
