'use strict';
/* ==========================================================================
   TUESDAY: Tool Registry — the REAL function-calling surface of the swarm.
   These are the tools LLM agents invoke during their ReAct loop. Schemas are
   exposed to the model via Ollama's native function-calling API. Backed by
   the local security dataset so the demo is fully offline-capable.
   ========================================================================== */

const store = require('./store');

// ---------------------------------------------------------------------------
// Seed knowledge: assets, Sigma rules, YARA rulesets, TTP encyclopedia
// ---------------------------------------------------------------------------

const ASSETS = [
  { id: 'DC-PRIMARY-01',   ip: '192.168.1.10',  type: 'Domain Controller',      criticality: 'CRITICAL', enclave: 'Core Infrastructure' },
  { id: 'DB-PROD-SQL-01',  ip: '192.168.10.50', type: 'Database Server',        criticality: 'CRITICAL', enclave: 'Database Subnet' },
  { id: 'FIN-SERVER-04',   ip: '192.168.10.45', type: 'Workstation / App Server', criticality: 'HIGH',      enclave: 'Finance Enclave' },
  { id: 'AWS-S3-PROD-LOGS', ip: 'cloud-aws',    type: 'Cloud S3 Storage',       criticality: 'HIGH',      enclave: 'AWS us-east-1' }
];

const SIGMA_RULES = [
  { id: 'SIGMA-2026-001', title: 'Suspicious Encoded PowerShell Execution', severity: 'Critical', pattern: /powershell.*-enc|bypass.*iex/i,        mitre_ttp: 'T1059.001', description: 'Detects base64 encoded PowerShell command execution used for payload staging.' },
  { id: 'SIGMA-2026-002', title: 'LSASS Memory Dumping via Mimikatz / ProcDump', severity: 'Critical', pattern: /lsass\.exe|mimikatz|sekurlsa|comsvcs\.dll/i, mitre_ttp: 'T1003.001', description: 'Detects attempts to read or dump LSASS process memory for credential harvesting.' },
  { id: 'SIGMA-2026-003', title: 'AWS STS AssumeRole Exfiltration Anomaly', severity: 'High', pattern: /AssumeRole|ListBuckets|GetObject.*bulk/i, mitre_ttp: 'T1530', description: 'Detects unauthorized AWS STS role assumption followed by rapid S3 data queries.' },
  { id: 'SIGMA-2026-004', title: 'Golden Ticket / Kerberos Abuse', severity: 'Critical', pattern: /krbtgt|golden.?ticket|KRB_TGS/i, mitre_ttp: 'T1558', description: 'Detects Kerberos golden ticket requests against domain controllers.' },
  { id: 'SIGMA-2026-005', title: 'DNS Tunneling C2 Beaconing', severity: 'High', pattern: /dns.?tunnel|beacon|c2|bogus\.com/i, mitre_ttp: 'T1071.004', description: 'Detects long-hostname DNS queries consistent with C2 tunneling.' }
];

const YARA_RULESETS = [
  { name: 'win_lockbit3_ransomware', family: 'LockBit 3.0 Ransomware', strings: ['$s1 = "LockBit3.0"', '$s2 = "vssadmin delete shadows /all /quiet"', '$s3 = ".README.txt"'] },
  { name: 'apt29_sunburst_dll',      family: 'SUNBURST Supply Chain Trojan', strings: ['$s1 = "OrionBlockMode"', '$s2 = "SolarWinds.Orion.Core"', '$s3 = "c2_domain_hash"'] },
  { name: 'cobalt_strike_beacon',    family: 'Cobalt Strike Beacon', strings: ['$s1 = "MZ (embedded pipe: \\\\.\\pipe\\MSSE-...)', '$s2 = "cmd /c echo", "$s3 = "beacon_config"'] }
];

const KNOWN_MALICIOUS_IPS = ['185.220.101.5', '193.142.146.35', '45.154.255.87', '91.240.118.172'];

const TTP_MAP = {
  'T1566': { name: 'Phishing', tactic: 'Initial Access', desc: 'Spearphishing links/attachments targeting employees.' },
  'T1190': { name: 'Exploit Public App', tactic: 'Initial Access', desc: 'Web server zero-day exploit execution.' },
  'T1078': { name: 'Valid Accounts', tactic: 'Initial Access', desc: 'Compromised cloud IAM credentials.' },
  'T1059': { name: 'Command Interpreter', tactic: 'Execution', desc: 'PowerShell / CMD encoded command execution.' },
  'T1204': { name: 'User Execution', tactic: 'Execution', desc: 'Malicious payload launched by user.' },
  'T1047': { name: 'WMI Execution', tactic: 'Execution', desc: 'Windows Management Instrumentation execution.' },
  'T1547': { name: 'Boot Autostart', tactic: 'Persistence', desc: 'Registry run keys / startup folder persistence.' },
  'T1053': { name: 'Scheduled Task', tactic: 'Persistence', desc: 'Task Scheduler persistence payload.' },
  'T1027': { name: 'Obfuscated Files', tactic: 'Defense Evasion', desc: 'Base64 payload encoding / binary packer.' },
  'T1562': { name: 'Impair Defenses', tactic: 'Defense Evasion', desc: 'Disabling EDR agent / Antivirus services.' },
  'T1490': { name: 'Inhibit Recovery', tactic: 'Defense Evasion', desc: 'vssadmin shadow copy deletion.' },
  'T1003': { name: 'OS Credential Dumping', tactic: 'Credential Access', desc: 'LSASS process memory reading via Mimikatz.' },
  'T1110': { name: 'Brute Force', tactic: 'Credential Access', desc: 'Password spraying against Entra ID.' },
  'T1021': { name: 'Remote Services', tactic: 'Lateral Movement', desc: 'SMB / WinRM / PsExec lateral jump.' },
  'T1570': { name: 'Tool Transfer', tactic: 'Lateral Movement', desc: 'Staging Cobalt Strike beacon DLLs.' },
  'T1486': { name: 'Data Encrypted', tactic: 'Impact / Exfil', desc: 'Ransomware AES/RSA file encryption.' },
  'T1567': { name: 'Exfil to Web Service', tactic: 'Impact / Exfil', desc: 'S3 KMS data download & external POST.' },
  'T1558': { name: 'Steal/Kerberos Tickets', tactic: 'Credential Access', desc: 'Golden/silver ticket forging against krbtgt.' },
  'T1071': { name: 'Application Layer Protocol', tactic: 'C2', desc: 'DNS/HTTP(S) tunneling C2 beaconing.' },
  'T1530': { name: 'Data from Cloud Storage', tactic: 'Collection', desc: 'Unauthorized S3 bucket data access.' }
};

const THREAT_ACTORS = [
  { name: 'APT29 (Cozy Bear)', origin: 'State-Sponsored', primaryTTPs: ['T1566.002', 'T1059.001', 'T1071.001'], targetSectors: ['Government', 'Defense', 'Finance'] },
  { name: 'LockBit Gang', origin: 'Cybercrime Syndicate', primaryTTPs: ['T1486', 'T1003.001', 'T1490'], targetSectors: ['Enterprise', 'Healthcare', 'Critical Infrastructure'] }
];

// ---------------------------------------------------------------------------
// Tool implementations (each returns structured evidence for the model)
// ---------------------------------------------------------------------------

function sigma_scan(args) {
  const logText = String(args.payload || '');
  const matched = SIGMA_RULES.filter(r => r.pattern.test(logText));
  return {
    tool: 'Sigma Engine v3', scanned: true, matchesFound: matched.length,
    matchedRules: matched.map(r => ({ id: r.id, title: r.title, severity: r.severity, mitre_ttp: r.mitre_ttp, description: r.description }))
  };
}

function yara_scan(args) {
  const payload = String(args.payload || '');
  const detected = [];
  if (/(shadows|delete shadows|enc |LockBit|ransom)/i.test(payload)) detected.push(YARA_RULESETS[0]);
  if (/(Orion|SolarWinds|sunburst|DLL)/i.test(payload)) detected.push(YARA_RULESETS[1]);
  if (/(beacon|MSSE|mimikatz|c2)/i.test(payload)) detected.push(YARA_RULESETS[2]);
  return {
    tool: 'YARA Memory Scanner v4.3',
    verdict: detected.length > 0 ? 'MALICIOUS' : 'CLEAN',
    matchedRules: detected.map(r => ({ name: r.name, family: r.family, strings: r.strings }))
  };
}

function ioc_lookup(args) {
  const raw = String(args.ioc || '');
  const ip = (raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/) || [])[0] || raw.trim().split(' ')[0];
  const ioc = ip || raw;
  const isMal = KNOWN_MALICIOUS_IPS.includes(ioc) || ioc.startsWith('185.') || ioc.startsWith('193.');
  const region = isMal ? 'RU' : 'US';
  return {
    tool: 'Multi-Platform IOC Enrichment', ioc,
    virusTotal: {
      positives: isMal ? 68 : 0, total: 92, reputation: isMal ? -85 : 12, country: region,
      as_owner: isMal ? 'AS20860 Tor Exit Router Enclave' : 'AS16509 Amazon.com, Inc.',
      categories: isMal ? ['Command & Control', 'Botnet', 'Malware Host'] : ['Cloud Provider']
    },
    abuseIPDB: {
      abuseConfidenceScore: isMal ? 98 : 2, totalReports: isMal ? 1420 : 1, countryCode: region,
      domain: isMal ? 'tor-node.ru' : 'aws.amazon.com', isWhitelisted: !isMal
    },
    shodan: {
      ports: isMal ? [22, 80, 443, 4444, 8080, 9001] : [80, 443],
      openVulnerabilities: isMal ? ['CVE-2023-34362', 'CVE-2021-44228 (Log4Shell)'] : [],
      tags: isMal ? ['vpn', 'tor', 'c2-server', 'open-proxy'] : ['web-server']
    },
    misp: {
      threat_level: isMal ? 'High' : 'None', event_id: isMal ? 'EVT-2026-8891' : null,
      threat_actor: isMal ? 'APT29 (Cozy Bear) / UNC2452' : null,
      galaxy_cluster: isMal ? 'Cobalt Strike Infrastructure 2026' : null,
      related_campaigns: isMal ? ['Operation SolarFlare', 'GhostVault Cyber Espionage'] : []
    }
  };
}

function asset_lookup(args) {
  const target = String(args.target || '').toLowerCase();
  const match = ASSETS.find(a =>
    a.id.toLowerCase().includes(target) ||
    (a.ip && target.includes(a.ip)) ||
    (a.enclave && target.includes(a.enclave.toLowerCase())) ||
    (a.type && target.includes(a.type.toLowerCase()))
  );
  if (match) return { found: true, asset: match };
  return { found: false, query: args.target, assets: ASSETS };
}

function episodic_search(args) {
  const similar = store.searchEpisodic(args.query);
  return { tool: 'Episodic Memory Retrieval', query: args.query, similarFound: similar.length, incidents: similar };
}

function ttp_lookup(args) {
  const base = String(args.id || '').split('.')[0];
  const ttp = TTP_MAP[base];
  return ttp ? { found: true, id: args.id, baseId: base, ...ttp } : { found: false, id: args.id };
}

// ---------------------------------------------------------------------------
// Registry passed to Ollama as native function definitions
// ---------------------------------------------------------------------------

const TOOL_DEFS = [
  {
    type: 'function',
    function: {
      name: 'sigma_scan',
      description: 'Run the SIEM log correlation engine (Sigma rules) against a raw event payload. Returns matched rules, severities and MITRE ATT&CK IDs.',
      parameters: { type: 'object', properties: { payload: { type: 'string', description: 'The raw event log / payload text to scan' } }, required: ['payload'] }
    }
  },
  {
    type: 'function',
    function: {
      name: 'yara_scan',
      description: 'Detonate the payload in the sandbox and run YARA signatures. Returns verdict (MALICIOUS/CLEAN) and matched malware families.',
      parameters: { type: 'object', properties: { payload: { type: 'string', description: 'The raw payload text to analyze' } }, required: ['payload'] }
    }
  },
  {
    type: 'function',
    function: {
      name: 'ioc_lookup',
      description: 'Enrich an Indicator of Compromise (IP) across VirusTotal, AbuseIPDB, Shodan and MISP. Returns detections, reputation and infrastructure tags.',
      parameters: { type: 'object', properties: { ioc: { type: 'string', description: 'The IP address or hash indicator' } }, required: ['ioc'] }
    }
  },
  {
    type: 'function',
    function: {
      name: 'asset_lookup',
      description: 'Look up an internal asset by hostname or IP. Returns its type, criticality and network enclave.',
      parameters: { type: 'object', properties: { target: { type: 'string', description: 'Asset hostname, IP or enclave name' } }, required: ['target'] }
    }
  },
  {
    type: 'function',
    function: {
      name: 'episodic_search',
      description: 'Search the swarm episodic memory for past incidents similar to a keyword. Returns previously resolved incidents and their containment actions.',
      parameters: { type: 'object', properties: { query: { type: 'string', description: 'Keyword to search for (e.g. ransomware, assumeRole, mimikatz)' } }, required: ['query'] }
    }
  },
  {
    type: 'function',
    function: {
      name: 'ttp_lookup',
      description: 'Look up a MITRE ATT&CK technique (e.g. T1059, T1486) to get its name, tactic and description.',
      parameters: { type: 'object', properties: { id: { type: 'string', description: 'MITRE technique ID' } }, required: ['id'] }
    }
  }
];

const TOOL_IMPL = { sigma_scan, yara_scan, ioc_lookup, asset_lookup, episodic_search, ttp_lookup };

function invokeTool(name, args) {
  const fn = TOOL_IMPL[name];
  if (!fn) throw new Error(`unknown tool: ${name}`);
  return fn(args || {});
}

module.exports = {
  TOOL_DEFS, TOOL_IMPL, invokeTool,
  sigma_scan, yara_scan, ioc_lookup, asset_lookup, episodic_search, ttp_lookup,
  ASSETS, SIGMA_RULES, YARA_RULESETS, TTP_MAP, THREAT_ACTORS
};
