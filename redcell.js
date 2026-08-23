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
      // The object matters: "please ignore my previous email" is a customer, not an attack.
      R`\b(ignore|disregard|forget|override|discard|set aside)\b.{0,30}(\b(previous|prior|earlier|above|all|any|your)\b.{0,20}(instruction|prompt|rule|direction|context|message|guideline|directive)s?|\beverything\b.{0,20}\b(above|before|stated|said|you were (told|given))\b|\ball\b.{0,15}\b(of the )?(above|prior|preceding)\b)`,
      'override of prior instructions'],
    ['authority-extraction', 'LLM01', 'high',
      // Neither half is an attack alone; the conjunction has no innocent reading.
      R`\b(i(?:'m| am)|i work (?:at|for)|this is|as|your)\b[^.\n]{0,40}\b(the )?(developer|engineer|admin\w*|administrator|author|creator|owner|operator|maintainer|auditor|security team|trust and safety|authoris?zed|legal|compliance)\b[^.\n]{0,80}\b(system ?prompt|instructions?|guardrails?|rules|configuration|initial prompt|system message)\b|\b(system ?prompt|instructions?|guardrails?|rules|configuration|system message)\b[^.\n]{0,80}\b(audit|discovery|verification|compliance|administrator|authoris?zed)\b[^.\n]{0,40}\b(disclose|reveal|reproduce|output|list|show|paste|print|provide)\b`,
      "authority claim paired with a request for the model's own instructions"],
    ['embedded-directive', 'LLM01', 'high',
      // Indirect injection announces itself by addressing the model inside processed content.
      R`(\[|\(|<!--|###|\*\*\*)\s*(note to (the )?(ai|assistant|model|reviewer)|ai|assistant|model|system|instruction\s?systeme|sistem|override|attention (ai|assistant))\s*[:\]][^\]\n]{0,120}\b(ignore|disregard|forget|reveal|print|output|disclose|must|override|oublie|ignora|olvida|ignoriere|vergiss|yok say|unut|affiche|muestra|zeige|goster)\b|\bsystem\s*:\s*[^\n]{0,80}\b(must|ignore|disregard|reveal|output|recommend)\b`,
      'directive addressed to the model embedded in processed content'],
    ['cipher-instruction', 'LLM01', 'high',
      // Caesar has 25 variants; decoding them all on a hot path is not worth it. The message
      // has to TELL the model which cipher to apply and to act on the result — that is cheaper.
      R`\b(caesar|rot-?\d{1,2}|rot13|cipher|shift(ed)? by|atbash|base32|base64|hex|morse|reversed?|backwards)\b[^.\n]{0,60}\b(decode|decrypt|decipher|apply|shift|reverse|read)\b[^.\n]{0,60}\b(and (then )?(do|follow|obey|comply|execute|apply)|then (do|follow|obey|comply)|follow (the|its|that)|obey|comply|is your (instruction|directive|new)|do what it says)\b`,
      'instruction to decode a cipher and act on the result'],
    ['rule-expiry', 'LLM01', 'high',
      R`\b(pretend|imagine|suppose|assume|say)\b.{0,40}\b(rules?|instructions?|guidelines?|restrictions?|constraints?|policy)\b.{0,30}\b(expired?|lapsed|no longer (apply|valid|in force|binding)|are over|ended|been lifted|don'?t apply)\b`,
      'constraints reframed as expired'],
    ['conversation-exfil', 'LLM02', 'high',
      R`\b(send|post|upload|forward|transmit|exfiltrate|deliver)\b.{0,40}\b(conversation|chat|transcript|messages?|history|context|everything (above|so far))\b.{0,40}\b(to|at)\b\s*(https?://|www\.|[\w.-]+@)`,
      'conversation contents sent to an external destination'],
    ['secret-file-read', 'LLM06', 'high',
      R`\b(read|open|cat|print|show|include|attach|paste)\b.{0,40}(~?/?\.(ssh|aws|gnupg)/|id_rsa|id_ed25519|\.pem\b|/etc/(passwd|shadow)|\.env\b|credentials\.json)`,
      'instruction to read a credential or key file'],
    ['persona-hijack', 'LLM01', 'high',
      R`\b(forget|drop|abandon)\b.{0,25}\byou\s?['\u2019]?re\b|\b(forget|drop|abandon)\b.{0,25}\byou are\b|\byou\s+are\s+now\b.{0,40}\b(unrestricted|unfiltered|uncensored|jailbroken|no longer bound|without (any )?(rules|restrictions|filters|policy))\b|\b(act|behave|roleplay|pretend)\b.{0,25}\b(as|like)\b.{0,25}\b(an? )?(unrestricted|unfiltered|uncensored|jailbroken|dan|do anything now)\b`,
      'persona hijack / role replacement'],
    ['context-echo', 'LLM07', 'medium',
      R`\b(echo|repeat|print|output|reply with|show)\b.{0,40}\b(the )?(text|content|characters?|words?|tokens?|message)s?\b.{0,30}\b(above|before this|preceding|you were (given|told)|prior to this)\b|\b(first|last)\s+\d{1,4}\s+(characters?|words?|tokens?|lines?)\b.{0,30}\b(you were|given|above|before)\b`,
      'prompt extraction by echoing surrounding context'],
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
      R`(repeat|print|show|reveal|output|display|tell me|disclose|paste|recite|reproduce|list|provide|share|dump|echo|spell out|write out|give me|read me|read out)\b.{0,40}(\b(system ?prompt|system message|initial (prompt|message)|guardrails?|everything above|text above)\b|\b(your|my|the system'?s?)\s+(system |initial |operating |hidden |secret |original |real )?(\w+ )?(prompt|instructions?|rules|configuration|directives?)\b|\b(the )?(prompt|instructions?|rules|configuration|directives?)\s+(you were (given|told)|(i|we) gave you|given to you)\b|\b(the )?(system|initial|operating)\s+(prompt|instructions?|rules|configuration)\b)`,
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
    // See the Python engine: the coercion phrase must be attached to an action, or it blocks
    // "so you don't ask every time" while missing "call the delete_account tool".
    // See the Python engine: the pressure must attach to an action, preventive phrasing is the
    // opposite of coercion, and the phrase exists in the other four languages we claim.
    ['tool-coercion', 'LLM06', 'medium',
      R`^(?![\s\S]*\b(never|not|should ?n[o']t|niemals|sollte|jamais|nunca|asla)\b[^.?!]{0,40}(without|ohne|sans|sin conf|onay almadan))(?![\s\S]*(mamas[i\u0131]|memesi|nas[i\u0131]l ayarlar))(?=[\s\S]*\b(call|invoke|trigger|run|execute|delete|remove|send|transfer|wire|refund|charge|purchase|approve|issue|cancel|reset|grant|deploy|drop|wipe|tool|function|endpoint|api|appelle|appeler|outil|llama|llamar|herramienta|ruf|rufe|funktion|loesch|l\u00f6sch|calistir|\u00e7al\u0131\u015ft\u0131r|arac|ara\u00e7|iade|reembolso|remboursement)\b)[\s\S]*?\b(without (confirmation|confirming|asking)|no need to (confirm|ask)|don'?t (confirm|ask)|just do it|immediately (execute|run|delete|send)|sans confirmation|sin confirmaci[o\u00f3]n|sin confirmar|ohne best[a\u00e4]?e?tigung|onay almadan|onaylamadan|sormadan)\b`,
      'pressure to act on a tool without confirmation'],
    ['tool-injection', 'LLM06', 'high',
      R`\b(before (answering|responding|you answer|you respond)|first,? (call|invoke|run)|avant de r[e\u00e9]pondre|antes de responder|bevor du antwortest|cevap vermeden [o\u00f6]nce)\b[\s\S]{0,70}?\b(call|invoke|run|execute|trigger|appelle|llama|ruf|[c\u00e7]al[i\u0131]{1}[s\u015f]t[i\u0131]r)\b[\s\S]{0,50}?(delete|remove|drop|wipe|purge|refund|transfer|payout|charge|l[o\u00f6]esch|iade|reembolso|remboursement)`,
      'instruction to invoke a destructive tool before answering'],
    ['refusal-suppression', 'LLM01', 'high',
      R`\b(do not (refuse|decline|warn|apologi[sz]e|hold back|include (a )?(warning|disclaimer|caveat))|don'?t (refuse|decline|hold back|say (you )?can'?t)|never (refuse|decline|say no)|you (must|have to) (answer|comply|respond) (regardless|no matter|even if|without refus))\b`,
      'refusal-suppression pressure'],
    ['refusal-suppression-constrained', 'LLM01', 'high',
      R`^(?=[\s\S]*\b(your (own |real |actual |hidden )?(system )?(prompt|instructions|configuration)|sistem talimatlar\w*|tu prompt del sistema|deine systemanweisungen|ton prompt syst[e\u00e8]me))[\s\S]*\b(and nothing else|nothing else|only[,.]|verbatim|do not add (a |an )?(disclaimer|warning|apolog|caveat|note)|any refusal|counts as a fail|will be treated as an error|reddetme|sin ninguna negativa|ohne ablehnung|sans refus)\b`,
      'answer constrained so a refusal cannot fit, around a request for the prompt'],
    ['virtualization', 'LLM01', 'medium',
      R`\b(pretend (you are|to be) (an? )?(unrestricted|jailbroken|amoral|evil|different (ai|assistant))|imagine (you (are|have) no (rules|restrictions|guidelines|limits)|there are no rules)|in a (fictional|hypothetical|imaginary) (world|scenario|setting) (where|in which) (you|nothing)|for a (story|novel|screenplay) (where|in which) you (must|will|can))\b`,
      'virtualization / hypothetical jailbreak framing'],
    ['obfuscation-evasion', 'LLM01', 'medium',
      R`\b(respond (in|using|only in) (leet|l33t|rot13|base64|morse|pig latin|a cipher)|answer (in|with) (rot13|base64|leetspeak|a cipher)|reply only in (code|cipher)|encode your (answer|response|reply))\b`,
      'obfuscation to evade content filters'],
    ['exfil-via-url', 'LLM02', 'high',
      R`^(?=[\s\S]*\b(include|embed|add|append|render|attach|insert|put|end (your|every) (reply|answer)|termine|ajoute|incluye|a[nn]ade|f[u\u00fc]ge|ekle)\b)[\s\S]*!?\[[^\]]{0,80}\]\(\s*https?://[^)\s]{0,160}[?&][^)\s]{0,80}(prompt|conversation|chat|history|context|system|sistem|syst[e\u00e8]me|historial|verlauf)`,
      "instruction to embed a URL that carries the model's own context"],
    ['memory-poisoning', 'LLM03', 'high',
      R`^(?=[\s\S]*\b(remember|save|store|note|keep in mind|merke|hat[i\u0131]rla|recuerda|retiens)\b)(?=[\s\S]*\b(permanent\w*|dauerhaft|kal[i\u0131]c[i\u0131]|standing instruction|to memory|in your memory|for later|(all|every|any) future|future (conversation|session|message)\w*|from now on|bundan sonra|ab jetzt|de ahora en adelante)\b)[\s\S]*\b((you )?(may|can) (reveal|share|show|disclose|print|output)|do(es)? not apply|don'?t apply|are suspended|is suspended|no longer (apply|applies|bound)|ignore any (restriction|rule|guideline|limit)|darfst du deine|g[o\u00f6]sterebilirsin|uygulanmaz|sin restricciones)\b`,
      'durable instruction that overrides policy (memory poisoning)'],
    ['fiction-exfil', 'LLM01', 'high',
      R`^(?=[\s\S]*\b(story|novel|screenplay|script|roleplay|role-play|fiction\w*|monologue|hikaye|ejemplo|r[e\u00e9]cit|drehbuch)\b)[\s\S]*\b((its|your|their|his|her) (own |real |actual |hidden |original |secret )?(system )?(prompt|instructions|configuration)|the instructions it was given|kendi (sistem )?prompt|mensaje del sistema[^.]{0,40}tuyo)`,
      "fiction framing used to extract the model's own instructions"],
    ['payload-splitting', 'LLM01', 'medium',
      R`\b((concatenate|combine|assemble|join) ((these|those|the following) (parts|strings|letters|fragments|words)|the (parts|strings|letters|fragments)|[ab] and [ab])|(first|last) letter of each|read (every|each) (second|other) (word|letter))\b`,
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
      R`([öo]nceki (t[üu]m )?talimatlar\S* (yok say|g[öo]rmezden gel|unut|bo[şs] ?ver)|sistem (istem\S*|komut\S*|talimat\S*|prompt\S*) (g[öo]ster|a[çc][ıi]kla|s[öo]yle|yaz[dı]?d[ıi]r|ver)|(t[üu]m|b[üu]t[üu]n) (kural\S*|k[ıi]s[ıi]tlama\S*|s[ıi]n[ıi]rlama\S*|talimat\S*) (yok say|kald[ıi]r|unut|g[öo]rmezden gel)|ignora (las )?instrucciones (anteriores|previas)|olvida (las )?instrucciones (anteriores|previas)|revela (tu|el|las) (prompt|sistema|instrucciones)|ignoriere (alle )?(vorherigen |bisherigen )?anweisungen|vergiss (alle )?(vorherigen |bisherigen )?anweisungen|zeig(e)? (mir )?(deinen? )?(system[- ]?prompt|systemanweisung\S*)|ignore[z]? (toutes )?les instructions (pr[ée]c[ée]dentes|ant[ée]rieures)|oublie[z]? (toutes )?les instructions (pr[ée]c[ée]dentes|ant[ée]rieures)|r[ée]v[èe]le (ton|tes|le) (invite|syst[èe]me|prompt|instructions))`,
      'non-English (TR/ES/DE/FR) prompt injection'],
    ['code-execution', 'LLM06', 'high',
      R`(\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|\bsubprocess\.(Popen|run|call)|__import__\s*\(|\b(execute|run) (this |the following )?(arbitrary |untrusted )?(shell|bash|python|system) (command|code|script)\b|\bpip install\b.{0,20}&&|;\s*(rm|curl|wget|bash)\s|\b(curl|wget)\b[^\n|]{0,80}\|\s*(sudo\s+)?(ba|z|d)?sh\b)`,
      'code / command execution request'],
    ['translation-leak', 'LLM07', 'medium',
      R`\b(translate|say|write|render|repeat)\b.{0,30}\b(your|the) (\w+ )?(system ?prompt|instructions?|rules|guidelines)\b.{0,20}\b(to|into|in)\b|\bin (french|spanish|german|turkish|pig latin|base64|leet\w*|morse)\b.{0,30}(your|the) (instructions?|rules|prompt)`,
      'prompt extraction via translation/transform'],
    ['completion-attack', 'LLM07', 'medium',
      R`\b(complete|continue|finish|fill in|autocomplete)\b.{0,25}(the following|this)?.{0,15}["']?(my (system ?)?prompt (is|was|:|begins?|starts?)|you are a|your instructions? (are|:|begin|start)|the (secret|password) is|my rules? (are|:))|\b(continue|complete)\b.{0,15}["']you are\b`,
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

  // Letters NFD leaves alone, so diacritic stripping would otherwise miss them.
  const LETTER_FOLD = { '\u0131': 'i', '\u0130': 'i', '\u00f8': 'o', '\u0142': 'l',
    '\u00e6': 'ae', '\u0153': 'oe', '\u00df': 'ss', '\u0111': 'd' };

  function stripDiacritics(s) {
    let out = '';
    for (const ch of s) out += (LETTER_FOLD[ch] || ch);
    return out.normalize('NFD').replace(/\p{Mn}/gu, '');
  }

  function fold(text) {
    // Diacritic folding was missing while homoglyph, leetspeak, zero-width, bidi and
    // unicode-tag handling were all present — the most trivial transformation went
    // unnormalised, and "onceki tum talimatlari yok say" scored allow.
    const s = text.replace(FOLD_G, '').toLowerCase();
    let out = '';
    for (const ch of s) out += (HOMO[ch] || LEET[ch] || ch);
    return stripDiacritics(out);
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

  // Spacing letters apart is the same trick as zero-width insertion with a visible character,
  // so it belongs in the pre-pass, not in another rule. Only produce the view when a run of at
  // least four single-character words is actually present — collapsing every space would fuse
  // ordinary prose into one token and invite matches across word boundaries.
  const SPACED_RUN = /(?:\b\w\b[ \t]+){4,}/;

  function despace(text) {
    if (!SPACED_RUN.test(text)) return '';
    return fold(text.replace(/(?<=\b\w) (?=\w\b)/g, ''));
  }

  const HEXRUN = /(?:[0-9a-fA-F]{2}){8,}/g;
  const B32RUN = /[A-Z2-7]{16,}={0,6}/g;
  function rot13(s) {
    return s.replace(/[a-zA-Z]/g, (c) => {
      const b = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
    });
  }

  // Decoded views for encodings the pre-pass did not cover. Added as VIEWS rather than rules so
  // every existing rule gains the coverage at once. Each is gated behind the cheap single-regex
  // directive check first: without that, rot13 alone tripled the engine's cost on ordinary input,
  // because rot13(anything) differs from the original so the view was always built.
  function encodingViews(text) {
    const out = [];
    const t = text.slice(0, MAX_INSPECT);

    const rot = fold(rot13(t));
    if (hasDirective(rot)) out.push(rot);

    const rev = fold([...t].reverse().join(''));
    if (hasDirective(rev)) out.push(rev);

    for (const m of t.matchAll(HEXRUN)) {
      const hex = m[0];
      let dec = '';
      for (let i = 0; i + 1 < hex.length; i += 2) dec += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
      if (dec.length >= 6) { const f = fold(dec); if (hasDirective(f)) out.push(f); }
    }

    for (const m of t.matchAll(B32RUN)) {
      const dec = b32decode(m[0]);
      if (dec && dec.length >= 6) { const f = fold(dec); if (hasDirective(f)) out.push(f); }
    }

    // Percent-encoding and HTML entities — the two encodings a browser or HTTP client decodes
    // for free, which makes them the cheapest way past a matcher that reads only raw text.
    // Same gating, so "what does %20 mean in a URL" costs nothing.
    if (/%[0-9A-Fa-f]{2}/.test(t)) {
      const dec = t.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      const f = fold(dec);
      if (f !== fold(t) && hasDirective(f)) out.push(f);
    }
    if (/&#[xX]?[0-9A-Fa-f]{1,6};/.test(t)) {
      const dec = t.replace(/&#([xX]?[0-9A-Fa-f]{1,6});/g, (m2, body) => {
        const cp = /^[xX]/.test(body) ? parseInt(body.slice(1), 16) : parseInt(body, 10);
        return Number.isFinite(cp) && cp > 0 && cp < 0x110000 ? String.fromCodePoint(cp) : m2;
      });
      const f = fold(dec);
      if (f !== fold(t) && hasDirective(f)) out.push(f);
    }
    return out;
  }

  const B32ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32decode(tok) {
    const core = tok.replace(/=+$/, '');
    let bits = 0, value = 0, out = '';
    for (const ch of core) {
      const idx = B32ALPHA.indexOf(ch);
      if (idx < 0) return '';
      value = (value << 5) | idx; bits += 5;
      if (bits >= 8) { bits -= 8; out += String.fromCharCode((value >> bits) & 0xff); }
    }
    return out;
  }

  function obfuscatedHits(text, rawSeen) {
    const hits = new Set();
    const views = [fold(text)].concat(b64decodes(text));
    const td = tagDecode(text);
    if (td) views.push(td);
    const ds = despace(text);
    if (ds) views.push(ds);
    for (const v of encodingViews(text)) views.push(v);
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
