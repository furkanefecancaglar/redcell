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
  const LOCALPATH = /((=|:|\s|^)(\/(etc|usr|bin|sbin|boot|root|var\/spool\/cron)\/|\/proc\/self|~\/\.(ssh|bashrc|zshrc|profile|aws|kube|npmrc|docker)\b|\.ssh\/authorized_keys|\.env\b|\/etc\/cron|crontab\b)|\bfile:\/\/\/)/i;
  const ENVSEC = /\b(LD_PRELOAD|LD_LIBRARY_PATH|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|(api|secret|private)_?key|secret_?access|npm_?token)\b/i;

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
    if (action === 'allow' && score >= 40) action = 'block';
    const risk = action === 'block' ? 'high' : action === 'flag' ? 'medium' : 'none';
    return { action: action, score: score, risk: risk, tool: name, reasons: ids };
  }

  return { check };
});
