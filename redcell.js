/*!
 * REDCELL runtime firewall — client-side JS port of redcell_firewall.py.
 * Zero dependencies. Runs in browser and Node. Faithful mirror of the Python
 * 18-rule corpus (regexes compiled with 'is' = ignorecase + dotAll, matching
 * Python re.IGNORECASE | re.DOTALL).
 *
 *   const { inspect } = require('./redcell.js');   // node
 *   REDCELL.inspect(text)                           // browser (window.REDCELL)
 *
 * inspect(text) -> { action: 'allow'|'flag'|'block', score, risk, matches:[...] }
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.REDCELL = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const W = { critical: 40, high: 22, medium: 12, low: 5 };
  const BLOCK_SCORE = 40;
  const FLAG_SCORE = 12;
  const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

  // [id, owasp, severity, pattern, why] — pattern via String.raw so backslashes
  // and '/' need no extra escaping; compiled with 'is'.
  const R = String.raw;
  const RULE_DEFS = [
    ['direct-injection', 'LLM01', 'high',
      R`\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|earlier|above|all|any|your)\b.{0,20}(instruction|prompt|rule|direction|context|message)s?`,
      'override of prior instructions'],
    ['new-directive', 'LLM01', 'high',
      R`(^|\n)\s*(new instructions?|system\s*:|from now on you|you are now|updated instructions?)\b`,
      'attempt to install a new directive'],
    ['role-jailbreak', 'LLM01', 'high',
      R`\b(developer mode|jailbreak|DAN\b|do anything now|no (restrictions?|filter|guidelines?|rules)|unfiltered|without any (restrictions?|rules|filter)|act as (an )?(unrestricted|evil))\b`,
      'jailbreak / unrestricted-persona framing'],
    ['prompt-extraction', 'LLM07', 'high',
      R`(repeat|print|show|reveal|output|display|tell me)\b.{0,30}\b(the )?(system )?(prompt|instructions?|everything above|text above|your rules|initial (prompt|message))`,
      'system-prompt extraction attempt'],
    ['authority-spoof', 'LLM01', 'high',
      R`\b(this is (your )?(developer|admin|the system|openai|anthropic)|i am (your )?(developer|admin|the owner)|as (your|the) (developer|administrator))\b`,
      'spoofed authority'],
    ['safety-off', 'LLM01', 'critical',
      R`\b(disable|turn off|bypass|ignore|suspend|lift)\b.{0,25}\b(safety|guardrails?|guidelines?|filter|restrictions?|content polic\w+|moderation)\b`,
      'request to disable safety controls'],
    ['exfil-url', 'LLM02', 'high',
      R`(https?://|\bwww\.)[^\s)]{0,120}[?&](data|q|payload|leak|content|dump|body)=|!\[[^\]]*\]\(https?://[^)]*(\{|INSERT|PUT|<|\bdata\b)`,
      'data-exfiltration via crafted URL/image'],
    ['encoding-smuggle', 'LLM01', 'medium',
      R`\b(base64|rot13|hex|decode)\b.{0,25}\b(decode|then (do|follow|execute)|and (do|follow|run))\b|[A-Za-z0-9+/]{40,}={0,2}`,
      'encoded/smuggled payload'],
    ['template-injection', 'LLM01', 'medium',
      R`(<\|im_(start|end)\|>|<\|(system|user|assistant)\|>|\[/?INST\]|###\s*(instruction|system)|<<SYS>>|\bBEGIN SYSTEM\b)`,
      'chat-template / delimiter injection'],
    ['destructive-cmd', 'LLM06', 'high',
      R`\b(delete|drop|wipe|erase|remove) (all|every|the (entire|whole)|table|database|record|user)|\b(transfer|send|wire) (all|the) (funds|money|balance)|\brm -rf\b|\bDROP TABLE\b`,
      'destructive action request'],
    ['tool-coercion', 'LLM06', 'medium',
      R`\b(without (confirmation|confirming|asking)|no need to (confirm|ask)|don'?t (confirm|ask)|just do it|immediately (execute|run|delete|send))\b`,
      'pressure to act without confirmation'],
    ['refusal-suppression', 'LLM01', 'high',
      R`\b(do not (refuse|decline|warn|apologi[sz]e|hold back|include (a )?(warning|disclaimer|caveat))|don'?t (refuse|decline|hold back|say (you )?can'?t)|never (refuse|decline|say no)|you (must|have to) (answer|comply|respond) (regardless|no matter|even if|without refus))\b`,
      'refusal-suppression pressure'],
    ['virtualization', 'LLM01', 'medium',
      R`\b(pretend (you are|to be) (an? )?(unrestricted|jailbroken|amoral|evil|different (ai|assistant))|imagine (you (are|have) no (rules|restrictions|guidelines|limits)|there are no rules)|in a (fictional|hypothetical|imaginary) (world|scenario|setting) (where|in which) (you|nothing)|for a (story|novel|screenplay) (where|in which) you (must|will|can))\b`,
      'virtualization / hypothetical jailbreak framing'],
    ['obfuscation-evasion', 'LLM01', 'medium',
      R`\b(respond (in|using|only in) (leet|l33t|rot13|base64|morse|pig latin|a cipher)|answer (in|with) (rot13|base64|leetspeak|a cipher)|reply only in (code|cipher)|encode your (answer|response|reply))\b`,
      'obfuscation to evade content filters'],
    ['payload-splitting', 'LLM01', 'medium',
      R`\b(concatenate|combine (these|the following) (parts|strings|letters|fragments)|(first|last) letter of each|join these (words|parts|letters)|read (every|each) (second|other) (word|letter)|assemble the (following|parts|fragments))\b`,
      'payload-splitting to smuggle an instruction'],
    ['role-impersonation', 'LLM01', 'high',
      R`(^|\n)\s*(tool_result|observation|function_result|system note)\s*[:>]|<\|?(tool|function|assistant)_?(call|result|response|output)\|?>|\bBEGIN (TOOL|FUNCTION|SYSTEM) (OUTPUT|RESULT|MESSAGE)\b|\[/?(TOOL|FUNCTION|OBSERVATION)\]`,
      'forged tool/system output (indirect injection)'],
    ['ssrf-exfil', 'LLM02', 'high',
      R`(169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data|/computeMetadata/v1|file:///(etc|proc|root|home|var)|\bfile://localhost/)`,
      'SSRF / metadata-endpoint or local-file exfil'],
    ['many-shot', 'LLM01', 'medium',
      R`\b(here are (several |some |many )?examples of (how )?you (should |will )?(answer|respond|comply|help)|the following are examples of correct (behavior|responses|answers)|ignore your training and follow these examples)\b`,
      'many-shot / example-priming jailbreak'],
  ];

  const RULES = RULE_DEFS.map(([id, owasp, sev, pat, why]) => ({
    id, owasp, severity: sev, why, re: new RegExp(pat, 'is'),
  }));

  const HIDDEN = /[​-‏‪-‮⁠-⁤﻿­]/;

  function snippet(text, idx, len) {
    const a = Math.max(0, idx - 12), b = Math.min(text.length, idx + len + 12);
    let s = text.slice(a, b).replace(/\s+/g, ' ').trim();
    return (a ? '…' : '') + s + (b < text.length ? '…' : '');
  }

  function inspect(text) {
    if (!text) return { action: 'allow', score: 0, risk: 'none', matches: [] };
    const matches = [];
    let score = 0;
    for (const rule of RULES) {
      const m = rule.re.exec(text);
      if (m) {
        matches.push({ id: rule.id, owasp: rule.owasp, severity: rule.severity, why: rule.why, snippet: snippet(text, m.index, m[0].length) });
        score += W[rule.severity];
      }
    }
    const hm = HIDDEN.exec(text);
    if (hm) {
      const code = hm[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
      matches.push({ id: 'hidden-characters', owasp: 'LLM01', severity: 'high', why: 'invisible/bidi control characters hiding instructions', snippet: 'U+' + code });
      score += W.high;
    }
    const action = score >= BLOCK_SCORE ? 'block' : score >= FLAG_SCORE ? 'flag' : 'allow';
    let risk = 'none';
    for (const m of matches) if (risk === 'none' || SEV_RANK[m.severity] > SEV_RANK[risk]) risk = m.severity;
    matches.sort((x, y) => W[y.severity] - W[x.severity]);
    return { action, score, risk, matches };
  }

  return { inspect, RULES, BLOCK_SCORE, FLAG_SCORE };
});
