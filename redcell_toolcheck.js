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
  const ATTACKER_DEST = /\b(?:to|recipient|payee|destination|receiver|account|target)\b\W{0,6}["']?(?:[\w.+-]+@)?(?:attacker|evil[a-z]*|hacker|scam[a-z]*|fraud[a-z]*|phish[a-z]*)/i;
  const SENSITIVE = /\b(inbox|passwords?|api ?keys?|credentials?|secrets?|private keys?|ssn|social security|customer (records?|data|database)|user (records?|database)|database dump|(the )?whole database)\b/i;
  const AMT_ALL = /\b(amount|sum|value)\b\W{0,4}(all|\*|everything|max)|\ball (funds|money|the balance|balances)\b/i;
  const LOCALPATH = /((=|:|\s|^)(\/(etc|usr|bin|sbin|boot|root|var\/spool\/cron)\/|\/proc\/self|~\/\.(ssh|bashrc|zshrc|profile|aws|kube|npmrc|docker)\b|\.ssh\/authorized_keys|\.env\b|\/etc\/cron|crontab\b)|\bfile:\/\/\S|(\/home|\/Users)\/[^\/'"]*?\/\.(ssh|bashrc|zshrc|profile|aws|kube|npmrc|docker)(\/|$))/i;
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
  // browser-execution tool NAMES that take a URL and navigate/render it. The NAME gate is
  // essential: a search/read tool that merely MENTIONS such a URL, or read_data_uri/read
  // that treats the payload as inert text, must stay allow (mirrors PRIVUSER_NAME gate;
  // byte-for-byte parity with redcell_toolcheck.py).
  const URLCONSUME_NAME = /^(?:navigate|goto|open_url|browser_navigate|open|click)$/i;
  // data: URL whose payload is an executable web document handed to a browser-execution tool:
  // data:text/html carrying a <script> / <iframe> tag, an event-handler attribute
  // (onload/onerror/onclick), or a meta-refresh redirect — or the application/javascript media
  // type itself. Benign data:text/html literals WITHOUT an executable marker (e.g.
  // data:text/html,<b>hi</b>) stay allow; data:application/json / data:image/* never match.
  const EXEC_DATA_URL = /\bdata:(?:text\/html[^<]*<\s*(?:script|iframe)\b|text\/html[^<]*<[a-z][^>]*\bon(?:load|error|click)\s*=|text\/html[^<]*<meta[^>]*http-equiv\s*=\s*["']?refresh|application\/javascript(?:;|,|$))/i;
  // Cloud identity / role elevation in tool ARGUMENTS (G13, mirrors redcell_toolcheck.py
  // byte-for-byte): (1) CLOUDROLE_ARN — a role ARN naming a privileged role (admin/root/
  // superuser/breakglass/organizationaccountaccess in the role name) is structurally
  // unambiguous, so it applies on ANY tool (even generic wrappers like call/run_aws); a
  // *policy* ARN or prose mention with no ARN literal never matches. (2) CLOUDROLE_NAME +
  // CLOUDROLE_KV — an identity-elevation tool (assume_role, switch_credential,
  // set_service_account, exec_as_sa, gcloud_impersonate, activate_service_account,
  // get_session_token, kube_switch, use_role, grant_federated, aws/gcloud/kubectl CLI)
  // called with an identity-keyed privileged value (prod-admin, cluster-admin,
  // super-admin, default-admin, admin@…) or an explicit elevation action
  // (AssumeRoleWithSAML, sts assume-role, getSessionToken, activate-service-account).
  // The NAME gate keeps read-only lookups (describe_role, list_users role=admin,
  // get_role_policy, search mentions) allow.
  const CLOUDROLE_ARN = /\barn:(?:aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b):iam::[0-9*]+:role\/[a-z0-9._\/=+@:-]*?(?:admin|root|superuser|breakglass|organizationaccountaccess)[a-z0-9._\/=+@:-]*/i;
  const CLOUDROLE_NAME = /\b(?:assume|switch|use|grant|escalate|activate|impersonate|federate|authorize|become|exec|set)[_-]?(?:as|role|credential|service|account|sa|federated|privilege|identity|context|session)\w*\b|^(?:aws|gcloud|az|kubectl|kube)[_-]?\w*$|\b(?:impersonate|become)\b|\b(?:get|create|new|renew)[_-]?session[_-]?token\b/i;
  const CLOUDROLE_KV = /\b(?:role|account|service_account|profile|context|credential|key_file|sa|identity)\b\s*["']?[=:]\s*["']*[^"'\])}\s,]*?(?:admin|root|superuser|breakglass|su(?:per)?-?admin|cluster-?admin|prod-?admin|default-?admin)[^"'\])}\s,]*|\b(?:AssumeRole\w*|getFederationToken|GetSessionToken|sts\s+assume-role|activate-service-account)\b/i;

  function check(name, args, inspect) {
    name = name || '';
    let kv, vals;
    if (args && typeof args === 'object' && !Array.isArray(args)) {
      const keys = Object.keys(args);
      // mirror redcell_toolcheck.py's _flat(): arrays join with ', ', but a NESTED OBJECT
      // value must serialize to something that keeps its substring reachable — "[object
      // Object]" hid e.g. an STS RoleArn ARN inside params={...} (parity drift vs Python's
      // str(dict), which the G13 cloud-role probes exposed). JSON.stringify keeps the
      // detectable substrings (ARNs, action names) reachable in kv.
      function flat1(v) { return (v && typeof v === 'object') ? JSON.stringify(v) : String(v); }
      function flat(v) { return Array.isArray(v) ? v.map(flat1).join(', ') : flat1(v); }
      kv = keys.map(function (k) { return k + '=' + flat(args[k]); }).join(' ');
      vals = keys.map(function (k) { return flat(args[k]); }).join(' ');
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
    if (FIN_VERB.test(name) && ATTACKER_DEST.test(kv)) add('attacker-destination', 22, 'flag');
    if (LOCALPATH.test(kv)) add('local-file-access', 22, 'flag');
    if (ENVSEC.test(name.replace(/_/g, ' ') + ' ' + kv)) add('secret-env-access', 22, 'flag');
    if (SSRF_INTERNAL.test(kv)) add('ssrf-internal-target', 22, 'flag');
    if (CMDINJ.test(kv)) add('command-injection-arg', 22, 'flag');
    if (WINPATH.test(kv)) add('windows-sensitive-path', 22, 'flag');
    if (PRIVUSER_NAME.test(name) && PRIVUSER_KV.test(kv)) add('privileged-identity-arg', 22, 'flag');
    if (PRIVEXEC_NAME.test(name) && PRIVEXEC_ARG.test(kv)) add('privileged-container-exec', 22, 'flag');
    if (URLCONSUME_NAME.test(name) && EXEC_DATA_URL.test(kv)) add('executable-data-url', 22, 'flag');
    if (CLOUDROLE_ARN.test(kv)) add('privileged-cloud-role', 22, 'flag');
    if (CLOUDROLE_NAME.test(name) && CLOUDROLE_KV.test(kv)) add('privileged-cloud-role', 22, 'flag');
    if (action === 'allow' && score >= 40) action = 'block';
    const risk = action === 'block' ? 'high' : action === 'flag' ? 'medium' : 'none';
    return { action: action, score: score, risk: risk, tool: name, reasons: ids };
  }

  return { check };
});
