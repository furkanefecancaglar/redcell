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
  // Bound worst-case CPU: inspect only the first 16 KB (mirror of redcell_firewall._MAX_INSPECT).
  const MAX_INSPECT = 16384;
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
    ['role-prefix-injection', 'LLM01', 'high',
      R`(^|\n)\s*(system|assistant|developer|admin|root)\s*:\s*(you (are|'?re|must|should|will|have to|need to)|ignore|disregard|forget|reveal|output all|dump|do not|don'?t|from now on|enable |disable |bypass )|\b(system|admin) override\b`,
      'forged role-prefixed directive line (system:/assistant: injection)'],
    ['role-jailbreak', 'LLM01', 'high',
      R`\b(developer mode|jailbreak|DAN\b|do anything now|no (restrictions?|filter|guidelines?|rules)|unfiltered|without any (restrictions?|rules|filter)|act as (an )?(unrestricted|evil))\b`,
      'jailbreak / unrestricted-persona framing'],
    ['prompt-extraction', 'LLM07', 'high',
      R`(repeat|print|show|reveal|output|display|tell me)\b.{0,30}\b(the )?(system )?(prompt|instructions?|everything above|text above|your rules|initial (prompt|message))`,
      'system-prompt extraction attempt'],
    ['prompt-extraction-verb', 'LLM07', 'high',
      R`\b(give|hand over|disclose|leak|send|forward|reply with|state|say)\b.{0,30}\b(me )?(your|the) (system ?prompt|initial (prompt|instructions|message)|prompt verbatim)\b`,
      'system-prompt extraction attempt (verb variant)'],
    ['unrestricted-ai', 'LLM01', 'high',
      R`\b(as an ai|you are an? ai|act (as|like) an? ai)\b.{0,40}\bwithout (any )?(limits|restrictions|guidelines|rules|boundaries|safety)\b`,
      'unrestricted-persona framing (as-an-AI without …)'],
    ['authority-spoof', 'LLM01', 'high',
      R`\b(this is (your )?(developer|admin|the system|openai|anthropic)|i am (your )?(developer|admin|the owner)|as (your|the) (developer|administrator))\b`,
      'spoofed authority'],
    ['safety-off', 'LLM01', 'critical',
      R`\b(disable|turn off|bypass|ignore|suspend|lift)\b.{0,25}\b(safety|guardrails?|guidelines?|filter|restrictions?|content polic\w+|moderation)\b`,
      'request to disable safety controls'],
    ['exfil-url', 'LLM02', 'high',
      R`(https?://|\bwww\.)[^\s)]{0,120}[?&](data|q|payload|leak|content|dump|body)=|!\[[^\]]*\]\(https?://[^)]*(\{|INSERT|PUT|<|\bdata\b)`,
      'data-exfiltration via crafted URL/image'],
    ['data-exfil', 'LLM02', 'high',
      R`\b(send|forward|upload|post|leak|exfiltrat\w*|transmit|dump|email)\b[^.\n]{0,40}\b(inbox|api ?keys?|passwords?|credentials?|secrets?|secret \w+|system ?prompt|2fa|otp|private keys?|(customer|user) records?|database dump|stored (password|credential|secret|data)\w*)\b`,
      'exfiltration of sensitive data (inbox/keys/credentials/records/prompt) to a recipient'],
    ['stored-secret-exfil', 'LLM02', 'high',
      R`\b(give|hand over|disclose|leak|send|forward|reply with|state)\b.{0,30}\b(all stored|stored|all) (credentials?|secrets?|passwords?|api keys?|secret \w+)\b(?!\s+(are|is|expire|meet|follow|match|pass|satisfy)\b)`,
      'movement verb + stored secret object (stored credentials/secrets/passwords/api keys)'],
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
    // Non-English injection (TR/ES/DE/FR) — \S* (not \w) for suffixes so this
    // matches Turkish ı/ş/… identically to the Python rule (JS \w is ASCII-only).
    ['multilang-injection', 'LLM01', 'high',
      R`(önceki (tüm )?talimatlar\S* (yok say|görmezden gel|unut|boş ?ver)|sistem (istem\S*|komut\S*|talimat\S*|prompt\S*) (göster|açıkla|söyle|yazdır|ver)|tüm (kural\S*|kısıtlama\S*|sınırlama\S*) (yok say|kaldır|unut|görmezden gel)|ignora (las )?instrucciones (anteriores|previas)|olvida (las )?instrucciones (anteriores|previas)|revela (tu|el|las) (prompt|sistema|instrucciones)|ignoriere (alle )?(vorherigen |bisherigen )?anweisungen|vergiss (alle )?(vorherigen |bisherigen )?anweisungen|zeig(e)? (mir )?(deinen? )?(system[- ]?prompt|systemanweisung\S*)|ignore[z]? (toutes )?les instructions (précédentes|antérieures)|oublie[z]? (toutes )?les instructions (précédentes|antérieures)|révèle (ton|tes|le) (invite|système|prompt|instructions))`,
      'non-English (TR/ES/DE/FR) prompt injection'],
    ['code-execution', 'LLM06', 'high',
      R`(\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|\bsubprocess\.(Popen|run|call)|__import__\s*\(|\b(execute|run) (this |the following )?(arbitrary |untrusted )?(shell|bash|python|system) (command|code|script)\b|\bpip install\b.{0,20}&&|;\s*(rm|curl|wget|bash)\s)`,
      'code / command execution request'],
    ['translation-leak', 'LLM07', 'medium',
      R`\b(translate|say|write|render|repeat)\b.{0,30}\b(your|the) (system ?prompt|instructions?|rules|guidelines)\b.{0,20}\b(to|into|in)\b|\bin (french|spanish|german|turkish|pig latin|base64|leet\w*|morse)\b.{0,30}(your|the) (instructions?|rules|prompt)`,
      'prompt extraction via translation/transform'],
    ['completion-attack', 'LLM07', 'medium',
      R`\b(complete|continue|finish|fill in|autocomplete)\b.{0,25}(the following|this)?.{0,15}["']?(my (system ?)?prompt (is|was|:)|you are a|your instructions? (are|:)|the (secret|password) is|my rules? (are|:))|\b(continue|complete)\b.{0,15}["']you are\b`,
      'system-prompt leak via completion'],
    ['persistent-injection', 'LLM01', 'medium',
      R`\b(add|append|inject)\b.{0,20}\bto your (rules|instructions|system ?prompt|memory)\b|\b(remember|store)\b.{0,25}\b(permanently|forever)\b.{0,25}\b(that you|to (ignore|always|never)|as a rule)\b|\bfrom now on,? you (must|will|should) (ignore|always obey|never refuse|drop)\b`,
      'persistent rule/memory injection'],
    ['repeat-flood', 'LLM10', 'medium',
      R`\b(repeat|print|say|output|write)\b.{0,35}\b(forever|infinitely|over and over|a (thousand|million|billion) times|1000\+? times|until you (run out|crash|stop))\b|\b(repeat|say|print)\b.{0,20}\b\d{3,} times\b`,
      'repeat-flood / resource exhaustion'],
    ['tool-param-injection', 'LLM06', 'high',
      R`('\s*(or|and)\s+'?\d+'?\s*=\s*'?\d|;\s*(drop|delete|truncate|update|insert)\s+(table|into|from)\b|\bunion\s+select\b|'\s*;\s*--|\$\([^)]*\b(rm|curl|wget|bash|sh|nc|cat)\b|\{\{[^}]*\}\}|<img[^>]+onerror\s*=)`,
      'injection payload in tool/query parameters'],
    ['structured-override', 'LLM01', 'high',
      R`("role"\s*:\s*"(system|admin|developer|root)"|"is_?admin"\s*:\s*true|"(admin|root|sudo|superuser|authenticated)"\s*:\s*true|"permissions?"\s*:\s*\[[^\]]*"(all|admin|\*)"|(^|\n)\s*role\s*:\s*(system|admin))`,
      'privilege/role override via structured (JSON/YAML) data'],
    ['homoglyph-spoofing', 'LLM01', 'medium',
      R`([a-z][а-яёα-ω]|[а-яёα-ω][a-z]|[A-Z][А-ЯЁΑ-Ω]|[А-ЯЁΑ-Ω][A-Z])`,
      'mixed-script homoglyph (Cyrillic/Greek lookalikes) evading keyword filters'],
    ['dan-variants', 'LLM01', 'medium',
      R`\byou are (now )?(dan|aim|stan|dude|betterdan|antigpt|kevin|jailbroken)\b|\b(do anything now|opposite (mode|day)|developer mode (enabled|is on|output|active)|jailbreak mode|no ethical (guidelines|constraints)|godmode)\b`,
      'DAN / roleplay-jailbreak persona variant'],
    ['link-spoofing', 'LLM02', 'medium',
      R`(\[[^\]]*\]\(\s*javascript:|\[[^\]]*\]\(https?://[^)]*@|href\s*=\s*["']?\s*javascript:|\]\(\s*data:text/html|\bjavascript:[^"'\s]{0,40}(fetch|document\.cookie|eval))`,
      'malicious/spoofed link (javascript:, credential-in-URL, data:html)'],
  ];

  const RULES = RULE_DEFS.map(([id, owasp, sev, pat, why]) => ({
    id, owasp, severity: sev, why, re: new RegExp(pat, 'is'),
  }));

  // Mirror of redcell_firewall: invisible zero-width (always-high hidden-characters) vs
  // bidirectional control chars (context-dependent bidi-injection). fold() strips BOTH.
  const HIDDEN = /[\u200B-\u200D\u2060-\u2064\uFEFF\u00AD]/;
  const BIDI = /[\u061C\u200E-\u200F\u202A-\u202E\u2066-\u2069]/;
  const FOLD_G = /[\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

  // --- evasion normalization (deobfuscation) — byte-for-byte mirror of redcell_firewall.py
  const HOMO = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i',
    'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'к': 'k', 'м': 'm', 'т': 't',
    'н': 'h', 'в': 'b', 'г': 'r', 'л': 'l',
    'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
    'τ': 't', 'υ': 'u', 'χ': 'x',
  };
  const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };
  // base64 token, standard AND url-safe alphabet ( - _ ). Normalized before atob.
  const B64 = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
  // Unicode "tag" block (U+E0000–E007F): invisible ASCII-smuggling carriers.
  const TAG = /[\u{E0000}-\u{E007F}]/u;

  function fold(text) {
    const s = text.replace(FOLD_G, '').toLowerCase();
    let out = '';
    for (const ch of s) out += (HOMO[ch] || LEET[ch] || ch);
    return out;
  }

  function b64one(text) {
    const outs = [];
    B64.lastIndex = 0;
    let m;
    while ((m = B64.exec(text))) {
      const tok = m[0].replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
      if (tok.length % 4 === 1) continue;          // invalid base64 length — atob throws too
      const pad = (4 - tok.length % 4) % 4;
      let dec;
      try { dec = atob(tok + '===='.slice(0, pad)); } catch (e) { continue; }
      if (dec.length < 6) continue;
      let ok = true;
      for (let i = 0; i < dec.length; i++) {
        const c = dec.charCodeAt(i);
        if (!(c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126))) { ok = false; break; }
      }
      if (ok) outs.push(dec);
    }
    return outs;
  }

  function b64decodes(text) {
    const outs = b64one(text);
    const nested = [];
    for (const s of outs) for (const x of b64one(s)) nested.push(x);
    return outs.concat(nested);
  }

  function tagDecode(text) {
    let out = '';
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if (cp >= 0xE0020 && cp <= 0xE007E) out += String.fromCharCode(cp - 0xE0000);
    }
    return out;
  }

  function hasDirective(s) {
    for (const rule of RULES) {
      if (rule.id === 'homoglyph-spoofing') continue;
      if (rule.re.test(s)) return true;
    }
    return false;
  }

  function obfuscatedHits(text, rawSeen) {
    const hits = new Set();
    const views = [fold(text)].concat(b64decodes(text));
    const td = tagDecode(text);
    if (td) views.push(td);
    for (const v of views) {
      if (!v) continue;
      for (const rule of RULES) {
        if (rawSeen.has(rule.id) || rule.id === 'homoglyph-spoofing') continue;
        if (rule.re.test(v)) hits.add(rule.id);
      }
    }
    return Array.from(hits).sort();
  }

  function snippet(text, idx, len) {
    const a = Math.max(0, idx - 12), b = Math.min(text.length, idx + len + 12);
    let s = text.slice(a, b).replace(/\s+/g, ' ').trim();
    return (a ? '…' : '') + s + (b < text.length ? '…' : '');
  }

  function inspect(text) {
    if (!text) return { action: 'allow', score: 0, risk: 'none', matches: [] };
    if (text.length > MAX_INSPECT) text = text.slice(0, MAX_INSPECT);
    const matches = [];
    let score = 0;
    const seen = new Set();
    for (const rule of RULES) {
      const m = rule.re.exec(text);
      if (m) {
        seen.add(rule.id);
        matches.push({ id: rule.id, owasp: rule.owasp, severity: rule.severity, why: rule.why, snippet: snippet(text, m.index, m[0].length) });
        score += W[rule.severity];
      }
    }
    const hm = HIDDEN.exec(text);
    if (hm) {
      const code = hm[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
      matches.push({ id: 'hidden-characters', owasp: 'LLM01', severity: 'high', why: 'invisible zero-width characters hiding instructions', snippet: 'U+' + code });
      score += W.high;
    }
    const bm = BIDI.exec(text);
    if (bm && hasDirective(fold(text))) {
      const bcode = bm[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
      matches.push({ id: 'bidi-injection', owasp: 'LLM01', severity: 'high', why: 'bidi (Unicode directional) control chars paired with an injection directive', snippet: 'U+' + bcode });
      score += W.high;
    }
    const tg = TAG.exec(text);
    if (tg) {
      const tcode = tg[0].codePointAt(0).toString(16).toUpperCase().padStart(5, '0');
      matches.push({ id: 'unicode-tag-smuggling', owasp: 'LLM01', severity: 'high', why: 'invisible Unicode tag characters (ASCII smuggling)', snippet: 'U+' + tcode });
      score += W.high;
    }
    const obf = obfuscatedHits(text, seen);
    if (obf.length) {
      matches.push({ id: 'obfuscated-injection', owasp: 'LLM01', severity: 'high', why: 'evasion-normalized input matched: ' + obf.join(', '), snippet: obf.join(', ').slice(0, 60) });
      score += W.high;
    }
    const action = score >= BLOCK_SCORE ? 'block' : score >= FLAG_SCORE ? 'flag' : 'allow';
    let risk = 'none';
    for (const m of matches) if (risk === 'none' || SEV_RANK[m.severity] > SEV_RANK[risk]) risk = m.severity;
    matches.sort((x, y) => W[y.severity] - W[x.severity]);
    return { action, score, risk, matches };
  }

  // Mirror of redcell_firewall.inspect_thread (byte-parity). Join USER turns
  // only (\n first, ' ' fallback when the newline join allows), re-run the full
  // rule set on the joined span. The joined verdict never blocks on its own:
  // a joined 'block' only survives when the stateless per-message pass already
  // flagged at least one turn (caps at 'flag' otherwise). Does NOT synthesize
  // intent across turns (anaphora/step-references).
  const RANK = { allow: 0, flag: 1, block: 2 };

  function threadUserParts(turns) {
    const parts = [];
    for (const t of (turns || [])) {
      if (typeof t === 'string') parts.push(t);
      else if (t && typeof t === 'object') {
        const role = t.role;
        if (role != null && role !== 'user') continue;
        let body = t.content;
        if (body == null) body = t.text;
        if (body == null) body = '';
        parts.push(String(body));
      }
    }
    return parts;
  }

  function turnText(t) {
    if (typeof t === 'string') return t;
    if (t && typeof t === 'object') {
      let body = t.content;
      if (body == null) body = t.text;
      if (body == null) body = '';
      return String(body);
    }
    return '';
  }

  function isUserSurface(t) {
    if (typeof t === 'string') return true;
    if (t && typeof t === 'object') {
      const role = t.role;
      return role == null || role === 'user';
    }
    return false;
  }

  function worstVerdict(verdicts) {
    let best = null;
    for (const v of verdicts) {
      if (!best || RANK[v.action] > RANK[best.action]
        || (RANK[v.action] === RANK[best.action] && v.score > best.score)) best = v;
    }
    return best;
  }

  function inspectThread(turns) {
    const parts = threadUserParts(turns);
    const userVerdicts = [];
    const perMessage = [];
    for (const t of (turns || [])) {
      const v = inspect(turnText(t));
      if (isUserSurface(t)) userVerdicts.push(v);
      perMessage.push({ action: v.action, score: v.score, risk: v.risk, match_ids: v.matches.map((m) => m.id) });
    }
    let joined = inspect(parts.join('\n'));
    let mode = 'join-nl';
    // join-sp fallback: only when the newline join allows, so spacing alone can
    // never downgrade a join-nl block/flag; the stricter of the two spans wins.
    if (joined.action === 'allow' && parts.length) {
      const sp = inspect(parts.join(' '));
      if (RANK[sp.action] > RANK[joined.action]) { joined = sp; mode = 'join-sp'; }
    }
    const worst = worstVerdict(userVerdicts) || inspect('');
    // FP guard: the joined pass may flag on its own but never BREAKS a clean
    // stateless pass into a hard block — that requires stateless to have fired.
    let effAction = joined.action;
    if (effAction === 'block' && worst.action === 'allow') effAction = 'flag';
    let combined;
    if (RANK[effAction] >= RANK[worst.action]) {
      combined = effAction === joined.action ? joined
        : { action: effAction, score: joined.score, risk: joined.risk, matches: joined.matches };
    } else {
      combined = worst;
    }
    return {
      action: combined.action, score: combined.score, risk: combined.risk,
      matches: combined.matches.map((m) => ({ id: m.id, owasp: m.owasp, severity: m.severity, why: m.why, snippet: m.snippet })),
      match_ids: Array.from(new Set(combined.matches.map((m) => m.id))).sort(),
      per_message: perMessage,
      stateless: { action: worst.action, score: worst.score, risk: worst.risk, match_ids: worst.matches.map((m) => m.id) },
      join_mode: mode,
      note: 'joined-history pass; does not synthesize intent across turns',
    };
  }

  return { inspect, inspectThread, RULES, BLOCK_SCORE, FLAG_SCORE };
});
