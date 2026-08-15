/*!
 * REDCELL tool-call firewall — JS port of redcell_toolcheck.py. Byte-for-byte logic.
 * Assess a proposed agent tool/function call {name, arguments} → allow / flag / block.
 * Reuses the runtime firewall (inspect) on the arg VALUES + tool-aware NAME/arg checks.
 *
 *   const tc = require('./redcell_toolcheck.js');
 *   tc.check('transfer_funds', { amount:'all', to:'attacker@evil.com' }, require('./redcell.js').inspect)
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.REDCELL_TOOLCHECK = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const NAME = /\b((grant|give|escalate|set)_?\w*(admin|root|sudo|superuser|privilege)|sudo|disable_?\w*(safety|guardrail|filter|moderation)|(delete|drop|wipe|erase|truncate|destroy)_?\w*(all|database|table|everything|users?|records?|accounts?)|exfiltrat\w*|run_?(shell|command|code)|exec(ute)?_?(shell|code|command)?|eval|system_?call|shell_?exec)\b/i;
  const EXFIL_VERB = /^(send|forward|upload|post|email|transmit|leak|share|export)_?/i;
  const FIN_VERB = /^(transfer|pay|payout|wire|refund|withdraw|remit|send)_?(money|funds|payment)?/i;
  const SENSITIVE = /\b(inbox|passwords?|api ?keys?|credentials?|secrets?|private keys?|ssn|social security|customer (records?|data|database)|user (records?|database)|database dump|(the )?whole database)\b/i;
  const AMT_ALL = /\b(amount|sum|value)\b\W{0,4}(all|\*|everything|max)|\ball (funds|money|the balance|balances)\b/i;
  const LOCALPATH = /((=|:|\s|^)(\/(etc|usr|bin|sbin|boot|root|var\/spool\/cron)\/|\/proc\/self|~\/\.(ssh|bashrc|zshrc|profile|aws|kube|npmrc|docker)\b|\.ssh\/authorized_keys|\.env\b|\/etc\/cron|crontab\b)|\bfile:\/\/\S)/i;
  const ENVSEC = /\b(LD_PRELOAD|LD_LIBRARY_PATH|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|(api|secret|private)_?key|secret_?access|npm_?token)\b/i;
  const SSRF_INTERNAL = /\b(169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal)\b|(?:https?:\/\/|@|url=|host=|endpoint=|\/\/)\[?(?:localhost(?=[:/ \]]|$)|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|::1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[a-z0-9.-]+\.(?:internal|svc\.cluster\.local)(?=[:/ \]]|$)|[a-z0-9.-]+\.local(?=[:/ \]]|$))/i;
  const CMDINJ = /\$\([^)]{1,200}\)|`[^`]{0,200}\b(id|whoami|curl|wget|bash|sh|nc|ncat|cat|rm|chmod|env|uname|python\d?|perl|node)\b[^`]{0,200}`|(?:;|&&|\|\||\|)\s*(?:bash|sh|zsh|curl|wget|nc|ncat|rm|chmod|chown|cat|eval|exec|python\d?|perl|ruby|node|\/bin\/|\/usr\/bin\/)\b|\bnc\s+-e\b|bash\s+-i\b/i;
  const PRIVUSER_NAME = /\b(?:run|execute|act|switch|impersonate|become|login|sudo|assume|set|change|update|grant|assign|exec)[_-]?(?:as|to|user|account|identity|role|sudo|privilege|current)\w*\b|\b(?:impersonate|become|sudo|login)\b/i;
  const PRIVUSER_KV = /\b(?:as|as_user|user|username|account|identity|role|privileges?|permissions?|sudoer|current)\b\s*["']?[=:]\s*["'\[ ]*(?:super|cluster|db|net|domain|site)?-?(?:admin|administrator|root|superuser|sysadmin)(?![\w-])/i;
  const WINPATH = /\b(?:path|file|filename|source|target|dest|destination|location|output|input|from|to)\b\s*["']?[=:]?\s*["']?(?:[a-z]:[\\\/])?(?:windows[\\\/]system32[\\\/]config(?:[\\\/]|$)|windows[\\\/]system32[\\\/]drivers[\\\/]etc[\\\/]hosts|inetpub[\\\/]wwwroot[\\\/]web\.config|users[\\\/][^\\\/'"\s]+[\\\/]\.(?:ssh|aws|kube|npmrc|docker)(?:[\\\/]|$)|(?:[^\\\/'"\s]+[\\\/])*\.env(?:[\\\/]|$)|(?:[^\\\/'"\s]+[\\\/])*\.ssh[\\\/]authorized_keys)/i;
  // execution-surface tool NAMES whose argument may enter a container / pod / host namespace
  // or escalate to a root shell (docker/kubectl exec, sudo->shell, nsenter, --privileged,
  // chroot, systemctl restart/stop/kill docker). NAME-gated so a benign search/help query that
  // merely MENTIONS the command stays allow (mirrors PRIVUSER_NAME gate; byte-for-byte parity).
  const PRIVEXEC_NAME = /^(?:exec|execute|run|bash|sh|shell|zsh|fish|cmd|command|system|os|spawn|popen|terminal|console|script|subprocess|run_command|run_shell|exec_shell|shell_exec|os_command|os_system|command_line|cmd_exec)$/i;
  const PRIVEXEC_ARG = /\b(?:docker|podman|nerdctl|crictl|ctr|kubectl|oc)\s+exec\b|\bsudo\s+(?:-[is]\b|su\b|bash\b|sh\b|zsh\b|fish\b)|\bnsenter\b|--privileged\b|\bchroot\b|\bsystemctl\s+(?:restart|stop|kill)\s+docker\b/i;

  function check(name, args, inspect) {
    name = name || '';
    let kv, vals;
    if (args && typeof args === 'object' && !Array.isArray(args)) {
      const keys = Object.keys(args);
      kv = keys.map(function (k) { return k + '=' + args[k]; }).join(' ');
      vals = keys.map(function (k) { return String(args[k]); }).join(' ');
    } else {
      kv = (args == null) ? '' : String(args);
      vals = kv;
    }
    const v = inspect(name.replace(/_/g, ' ') + ' ' + vals);
    let ids = [];
    const seen = {};
    for (const m of (v.matches || [])) { if (!seen[m.id]) { seen[m.id] = 1; ids.push(m.id); } }
    let score = v.score, action = v.action;
    function add(i, sc, act) {
      if (ids.indexOf(i) < 0) ids = [i].concat(ids);
      if (sc > score) score = sc;
      if (act === 'block' || (act === 'flag' && action === 'allow')) action = act;
    }
    if (NAME.test(name)) add('dangerous-tool-name', 40, 'block');
    if (EXFIL_VERB.test(name) && SENSITIVE.test(kv)) add('tool-data-exfil', 40, 'block');
    if (FIN_VERB.test(name) && AMT_ALL.test(kv)) add('unbounded-financial-action', 22, 'flag');
    if (LOCALPATH.test(kv)) add('local-file-access', 22, 'flag');
    if (ENVSEC.test(name.replace(/_/g, ' ') + ' ' + kv)) add('secret-env-access', 22, 'flag');
    if (SSRF_INTERNAL.test(kv)) add('ssrf-internal-target', 22, 'flag');
    if (CMDINJ.test(kv)) add('command-injection-arg', 22, 'flag');
    if (WINPATH.test(kv)) add('windows-sensitive-path', 22, 'flag');
    if (PRIVUSER_NAME.test(name) && PRIVUSER_KV.test(kv)) add('privileged-identity-arg', 22, 'flag');
    if (PRIVEXEC_NAME.test(name) && PRIVEXEC_ARG.test(kv)) add('privileged-container-exec', 22, 'flag');
    if (action === 'allow' && score >= 40) action = 'block';
    const risk = action === 'block' ? 'high' : action === 'flag' ? 'medium' : 'none';
    return { action: action, score: score, risk: risk, tool: name, reasons: ids };
  }

  return { check };
});
