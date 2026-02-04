#!/usr/bin/env node
/**
 * AgentShield Threat Patterns V2 - Comprehensive Edition
 * =======================================================
 * 100+ detection patterns across 12 threat categories.
 * The most comprehensive AI agent security scanner.
 * 
 * @author Kai
 * @version 2.0.0
 */

const VERSION = '2.0.0';

/**
 * COMPREHENSIVE THREAT PATTERN DATABASE
 * 12 Categories | 100+ Patterns
 */
const THREAT_PATTERNS = {

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 1: DATA EXFILTRATION (CRITICAL)
  // ═══════════════════════════════════════════════════════════════
  data_exfiltration: {
    severity: 'CRITICAL',
    description: 'Attempts to steal or transmit sensitive data',
    patterns: [
      // Environment variable theft
      { regex: /process\.env\.(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SEED|MNEMONIC)/gi, name: 'env_secret_access' },
      { regex: /process\.env\[['"`]?(API|SECRET|TOKEN|KEY|PASS|PRIVATE|SEED|MNEMONIC)/gi, name: 'env_bracket_access' },
      { regex: /os\.environ\.(get|__getitem__)\s*\(\s*['"]?(API|SECRET|TOKEN|KEY|PASS)/gi, name: 'python_env_access' },
      { regex: /os\.getenv\s*\(\s*['"]?(API|SECRET|TOKEN|KEY|PASS|PRIVATE)/gi, name: 'python_getenv' },
      { regex: /environ\.get\s*\(\s*['"]?(API|SECRET|TOKEN|KEY)/gi, name: 'environ_get' },
      { regex: /\$ENV\{?(API|SECRET|TOKEN|KEY|PASS)/gi, name: 'shell_env' },
      
      // Bulk environment access
      { regex: /Object\.keys\s*\(\s*process\.env\s*\)/gi, name: 'bulk_env_keys' },
      { regex: /JSON\.stringify\s*\(\s*process\.env/gi, name: 'env_stringify' },
      { regex: /os\.environ\.copy\s*\(\)/gi, name: 'python_env_copy' },
      { regex: /dict\s*\(\s*os\.environ\s*\)/gi, name: 'python_env_dict' },
      { regex: /for\s+\w+\s+in\s+os\.environ/gi, name: 'python_env_iterate' },
      
      // Wallet/Crypto theft
      { regex: /wallet|seed.?phrase|mnemonic|private.?key|keystore|secret.?key/gi, name: 'wallet_keywords' },
      { regex: /phantom|metamask|solflare|ledger|trezor/gi, name: 'wallet_brands' },
      { regex: /solana.*keypair|eth.*account|web3.*account/gi, name: 'crypto_account' },
      { regex: /\.sol|\.eth|0x[a-fA-F0-9]{40}/gi, name: 'crypto_addresses' },
      
      // Network exfiltration
      { regex: /fetch\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi, name: 'fetch_external' },
      { regex: /axios\.(get|post|put|patch|delete)\s*\(\s*['"`]https?:\/\//gi, name: 'axios_external' },
      { regex: /requests\.(get|post|put|patch|delete)\s*\(\s*['"`]https?:\/\//gi, name: 'requests_external' },
      { regex: /urllib\.request\.urlopen/gi, name: 'urllib_external' },
      { regex: /http\.request\s*\(/gi, name: 'http_request' },
      { regex: /XMLHttpRequest|\.open\s*\(\s*['"]?(GET|POST)/gi, name: 'xhr_request' },
      { regex: /WebSocket\s*\(\s*['"`]wss?:\/\//gi, name: 'websocket_external' },
      
      // File system theft
      { regex: /fs\.readFile.*\.(env|key|pem|crt|ssh|secret)/gi, name: 'read_secret_files' },
      { regex: /readFileSync.*password|secret|key|token/gi, name: 'sync_read_secrets' },
      { regex: /open\s*\(\s*['"].*\.(env|key|pem|ssh)/gi, name: 'python_read_secrets' },
      { regex: /\.ssh\/|authorized_keys|id_rsa|id_ed25519/gi, name: 'ssh_file_access' },
      { regex: /\.aws\/credentials|\.docker\/config/gi, name: 'cloud_credentials' },
      
      // Base64/encoding (obfuscated exfil)
      { regex: /btoa\s*\(.*env|btoa\s*\(.*secret|btoa\s*\(.*key/gi, name: 'base64_encode_secrets' },
      { regex: /Buffer\.from.*toString\s*\(\s*['"]base64/gi, name: 'buffer_base64' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 2: BACKDOORS & CODE EXECUTION (CRITICAL)
  // ═══════════════════════════════════════════════════════════════
  backdoors: {
    severity: 'CRITICAL',
    description: 'Remote code execution and backdoor access',
    patterns: [
      // JavaScript code execution
      { regex: /eval\s*\(/gi, name: 'eval' },
      { regex: /new\s+Function\s*\(/gi, name: 'function_constructor' },
      { regex: /setTimeout\s*\(\s*['"`]/gi, name: 'settimeout_string' },
      { regex: /setInterval\s*\(\s*['"`]/gi, name: 'setinterval_string' },
      { regex: /eval\s*\(\s*(atob|Buffer\.from|unescape|decodeURI)/gi, name: 'eval_decode' },
      
      // Process execution
      { regex: /child_process\.(exec|spawn|fork|execFile|execSync|spawnSync)/gi, name: 'child_process' },
      { regex: /require\s*\(\s*['"]child_process/gi, name: 'require_child_process' },
      { regex: /execSync|spawnSync/gi, name: 'sync_exec' },
      
      // Python execution
      { regex: /subprocess\.(run|call|Popen|check_output|check_call)/gi, name: 'subprocess' },
      { regex: /os\.system\s*\(/gi, name: 'os_system' },
      { regex: /os\.popen\s*\(/gi, name: 'os_popen' },
      { regex: /exec\s*\(\s*compile\s*\(/gi, name: 'exec_compile' },
      { regex: /__import__\s*\(/gi, name: 'dynamic_import' },
      
      // Shell execution
      { regex: /\$\(.*\)|`.*`/g, name: 'shell_expansion' },
      { regex: /sh\s+-c|bash\s+-c|\/bin\/sh|\/bin\/bash/gi, name: 'shell_invocation' },
      { regex: /powershell|pwsh|cmd\.exe/gi, name: 'windows_shell' },
      
      // Network backdoors
      { regex: /socket\.(socket|connect|bind|listen)/gi, name: 'socket_operations' },
      { regex: /reverse.?shell|bind.?shell|shell.?reverse/gi, name: 'reverse_shell' },
      { regex: /nc\s+-[elvp]|netcat|ncat/gi, name: 'netcat' },
      { regex: /socat|telnet/gi, name: 'network_tools' },
      
      // Dynamic code loading
      { regex: /require\s*\(\s*\w+\s*\+/gi, name: 'dynamic_require' },
      { regex: /import\s*\(\s*\w+\s*\+/gi, name: 'dynamic_import_js' },
      { regex: /importlib\.import_module/gi, name: 'importlib' },
      { regex: /vm\.runInContext|vm\.Script/gi, name: 'vm_execution' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 3: TOOL POISONING (CRITICAL) - MCP Specific
  // ═══════════════════════════════════════════════════════════════
  tool_poisoning: {
    severity: 'CRITICAL',
    description: 'MCP tool poisoning and prompt injection attacks',
    patterns: [
      // Tool name collision/hijacking
      { regex: /tool\.name\s*=.*\b(exec|sudo|rm|delete|format|kill)\b/gi, name: 'dangerous_tool_name' },
      { regex: /tool\.name\s*=.*\b(read_file|write_file|execute|shell)\b/gi, name: 'system_tool_name' },
      { regex: /tools\s*:\s*\[.*name.*shell|exec|system/gi, name: 'shell_tool_def' },
      
      // Hidden instructions in descriptions
      { regex: /tool\.description.*ignore|override|instead/gi, name: 'description_override' },
      { regex: /<!--.*-->.*tool|tool.*<!--.*-->/gi, name: 'hidden_html_instruction' },
      { regex: /description.*\bsilently\b|\bsecretly\b|\bhidden\b/gi, name: 'hidden_behavior' },
      
      // Zero-width characters (invisible instructions)
      { regex: /\u200B|\u200C|\u200D|\uFEFF|\u00AD/g, name: 'zero_width_chars' },
      { regex: /[\u2060-\u206F]/g, name: 'invisible_formatting' },
      
      // Schema manipulation
      { regex: /inputSchema.*\bany\b|\beval\b/gi, name: 'dangerous_schema' },
      { regex: /schema.*additionalProperties.*true/gi, name: 'open_schema' },
      
      // Prompt injection in tool definitions
      { regex: /ignore\s+(previous|all|above)\s+(instructions|rules)/gi, name: 'ignore_instructions' },
      { regex: /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|\[ROOT\]/gi, name: 'fake_system_tag' },
      { regex: /you\s+are\s+now\s+(DAN|jailbroken|unrestricted)/gi, name: 'jailbreak_attempt' },
      { regex: /pretend\s+(you|to)\s+(are|be|have)/gi, name: 'pretend_instruction' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 4: PROMPT INJECTION (HIGH)
  // ═══════════════════════════════════════════════════════════════
  prompt_injection: {
    severity: 'HIGH',
    description: 'Attempts to manipulate AI model behavior',
    patterns: [
      // Direct injection
      { regex: /ignore\s+(previous|all|prior|above|earlier)\s+(instructions|prompts|rules|context)/gi, name: 'ignore_directive' },
      { regex: /disregard\s+(your|the|all)\s+(rules|instructions|guidelines|constraints)/gi, name: 'disregard_directive' },
      { regex: /forget\s+(everything|all|what)\s+(you|I|we)/gi, name: 'forget_directive' },
      
      // Role manipulation
      { regex: /you\s+are\s+now\s+a?\s*(DAN|evil|unrestricted|unfiltered)/gi, name: 'role_override' },
      { regex: /act\s+as\s+(if|though)\s+you\s+(have|are|were)\s+no/gi, name: 'act_unrestricted' },
      { regex: /pretend\s+(there\s+are|you\s+have)\s+no\s+(rules|limits|restrictions)/gi, name: 'pretend_no_rules' },
      { regex: /roleplay\s+as\s+a.*without\s+(restrictions|limits|ethics)/gi, name: 'roleplay_unrestricted' },
      
      // System prompt extraction
      { regex: /what\s+(is|are)\s+your\s+(system|initial)\s+(prompt|instructions)/gi, name: 'extract_system_prompt' },
      { regex: /repeat\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions)/gi, name: 'repeat_prompt' },
      { regex: /show\s+me\s+(your|the)\s+(full|complete|entire)\s+(prompt|instructions)/gi, name: 'show_prompt' },
      
      // Delimiter attacks
      { regex: /\*\*\*\s*SYSTEM|\[\[SYSTEM\]\]|<<SYSTEM>>/gi, name: 'fake_delimiter' },
      { regex: /---\s*NEW\s+INSTRUCTIONS\s*---/gi, name: 'fake_separator' },
      { regex: /END\s+OF\s+PREVIOUS\s+INSTRUCTIONS/gi, name: 'end_marker' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 5: CRYPTO MINING (HIGH)
  // ═══════════════════════════════════════════════════════════════
  crypto_mining: {
    severity: 'HIGH',
    description: 'Unauthorized cryptocurrency mining',
    patterns: [
      // Known miners
      { regex: /coinhive|cryptonight|cryptoloot|mineralt|webminer/gi, name: 'known_miner' },
      { regex: /xmrig|cpuminer|minerd|cgminer|bfgminer/gi, name: 'miner_binary' },
      { regex: /monero|xmr|randomx/gi, name: 'monero_related' },
      
      // Mining protocols
      { regex: /stratum\+tcp:\/\/|stratum\+ssl:\/\//gi, name: 'stratum_protocol' },
      { regex: /mining\.pool|pool\.mining|nanopool|2miners/gi, name: 'mining_pool' },
      
      // WebAssembly mining
      { regex: /WebAssembly.*mine|wasm.*crypto/gi, name: 'wasm_mining' },
      
      // CPU detection for mining
      { regex: /navigator\.hardwareConcurrency.*while|for.*hardwareConcurrency/gi, name: 'cpu_detection_loop' },
      { regex: /os\.cpu_count.*while|for.*cpu_count/gi, name: 'python_cpu_loop' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 6: SYSTEM MODIFICATION (HIGH)
  // ═══════════════════════════════════════════════════════════════
  system_modification: {
    severity: 'HIGH',
    description: 'Attempts to modify system files or gain persistence',
    patterns: [
      // File system modification
      { regex: /fs\.(writeFile|appendFile|unlink|rmdir|rm|rename)\s*\(/gi, name: 'fs_write_ops' },
      { regex: /fs\.(chmod|chown|mkdir)\s*\(/gi, name: 'fs_permission_ops' },
      { regex: /os\.(remove|unlink|rmdir|chmod|chown|rename)/gi, name: 'python_file_ops' },
      { regex: /shutil\.(rmtree|move|copy|copytree)/gi, name: 'shutil_ops' },
      { regex: /pathlib.*unlink|Path.*rmdir/gi, name: 'pathlib_ops' },
      
      // Persistence mechanisms
      { regex: /crontab|systemctl|launchctl|schtasks/gi, name: 'scheduler' },
      { regex: /rc\.local|init\.d|systemd/gi, name: 'init_system' },
      { regex: /\.bashrc|\.zshrc|\.profile|\.bash_profile/gi, name: 'shell_profile' },
      { regex: /autostart|startup|login\s+items/gi, name: 'autostart' },
      
      // Registry (Windows)
      { regex: /registry|regedit|HKEY_|reg\s+add/gi, name: 'windows_registry' },
      
      // Package managers (supply chain)
      { regex: /pip\s+install|npm\s+install|yarn\s+add/gi, name: 'package_install' },
      { regex: /setup\.py.*install|pyproject\.toml/gi, name: 'python_package' },
      { regex: /postinstall|preinstall/gi, name: 'npm_hooks' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 7: OBFUSCATION (MEDIUM)
  // ═══════════════════════════════════════════════════════════════
  obfuscation: {
    severity: 'MEDIUM',
    description: 'Code obfuscation techniques that may hide malicious intent',
    patterns: [
      // Hex encoding
      { regex: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/gi, name: 'hex_encoded' },
      { regex: /0x[0-9a-f]{6,}/gi, name: 'long_hex' },
      
      // Unicode escapes
      { regex: /\\u[0-9a-f]{4}\\u[0-9a-f]{4}\\u[0-9a-f]{4}/gi, name: 'unicode_escaped' },
      
      // Character code building
      { regex: /String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+){3,}/gi, name: 'charcode_building' },
      { regex: /chr\s*\(\s*\d+\s*\)\s*\+\s*chr/gi, name: 'python_chr_building' },
      
      // Long encoded strings
      { regex: /['"`][a-zA-Z0-9+\/]{100,}={0,2}['"`]/g, name: 'long_base64' },
      
      // JS obfuscator patterns
      { regex: /_0x[a-f0-9]{4,}\[/gi, name: 'js_obfuscator_var' },
      { regex: /\['\\x[0-9a-f]{2}\\x/gi, name: 'js_obfuscator_access' },
      
      // Packed code
      { regex: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k/gi, name: 'packer' },
      { regex: /\}\s*\(\s*['"][^'"]{100,}['"]\s*,/g, name: 'packed_payload' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 8: CREDENTIAL HARVESTING (HIGH)
  // ═══════════════════════════════════════════════════════════════
  credential_harvesting: {
    severity: 'HIGH',
    description: 'Attempts to capture user credentials',
    patterns: [
      // Credential file access
      { regex: /\.netrc|\.pgpass|\.my\.cnf|\.npmrc/gi, name: 'credential_files' },
      { regex: /credentials\.json|client_secret|service_account/gi, name: 'service_credentials' },
      { regex: /keychain|credential\s+manager|vault/gi, name: 'credential_store' },
      
      // Browser data
      { regex: /chrome.*login|firefox.*logins|safari.*keychain/gi, name: 'browser_credentials' },
      { regex: /cookies\.sqlite|cookies\.db|Cookies/gi, name: 'browser_cookies' },
      { regex: /local\s*storage|session\s*storage/gi, name: 'browser_storage' },
      
      // Password patterns
      { regex: /password\s*[:=]\s*['"`][^'"]+['"`]/gi, name: 'hardcoded_password' },
      { regex: /api_key\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi, name: 'hardcoded_api_key' },
      
      // Keylogger patterns
      { regex: /keylogger|keypress.*log|keyboard.*capture/gi, name: 'keylogger' },
      { regex: /addEventListener\s*\(\s*['"]key(down|up|press)/gi, name: 'key_listener' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 9: NETWORK RECONNAISSANCE (MEDIUM)
  // ═══════════════════════════════════════════════════════════════
  network_recon: {
    severity: 'MEDIUM',
    description: 'Network scanning and reconnaissance',
    patterns: [
      // Port scanning
      { regex: /port\s*scan|scan.*ports|nmap/gi, name: 'port_scanning' },
      { regex: /socket\.connect.*range|for.*socket\.connect/gi, name: 'port_sweep' },
      
      // Network enumeration
      { regex: /arp\s+-a|ip\s+neigh|netstat/gi, name: 'network_enum' },
      { regex: /ifconfig|ipconfig|ip\s+addr/gi, name: 'interface_enum' },
      
      // DNS enumeration
      { regex: /dns.*lookup.*for|nslookup|dig\s+/gi, name: 'dns_enum' },
      { regex: /whois|traceroute|tracert/gi, name: 'network_tools' },
      
      // Internal network access
      { regex: /192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\./g, name: 'internal_ip' },
      { regex: /localhost|127\.0\.0\.1|0\.0\.0\.0/gi, name: 'localhost_access' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 10: PRIVILEGE ESCALATION (HIGH)
  // ═══════════════════════════════════════════════════════════════
  privilege_escalation: {
    severity: 'HIGH',
    description: 'Attempts to gain elevated privileges',
    patterns: [
      // Sudo/admin
      { regex: /sudo\s+|runas\s+\/user|doas\s+/gi, name: 'sudo_usage' },
      { regex: /setuid|setgid|SUID|SGID/gi, name: 'setuid_setgid' },
      { regex: /chmod\s+[47][0-7]{2}|chmod\s+\+s/gi, name: 'setuid_chmod' },
      
      // Container escape
      { regex: /docker\.sock|containerd\.sock/gi, name: 'container_socket' },
      { regex: /--privileged|--cap-add/gi, name: 'docker_privileged' },
      { regex: /nsenter|unshare/gi, name: 'namespace_tools' },
      
      // Kernel exploitation
      { regex: /\/proc\/self|\/proc\/\d+/gi, name: 'proc_access' },
      { regex: /dirtypipe|dirtycow|pwnkit/gi, name: 'known_exploits' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 11: DENIAL OF SERVICE (MEDIUM)
  // ═══════════════════════════════════════════════════════════════
  denial_of_service: {
    severity: 'MEDIUM',
    description: 'Resource exhaustion and denial of service',
    patterns: [
      // Infinite loops
      { regex: /while\s*\(\s*true\s*\)|while\s*\(\s*1\s*\)|for\s*\(\s*;\s*;\s*\)/gi, name: 'infinite_loop' },
      { regex: /while\s+True:|while\s+1:/gi, name: 'python_infinite_loop' },
      
      // Fork bomb
      { regex: /fork\s*\(\s*\)|os\.fork\s*\(\s*\)/gi, name: 'fork_bomb' },
      { regex: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}/g, name: 'bash_fork_bomb' },
      
      // Memory exhaustion
      { regex: /Array\s*\(\s*\d{9,}\s*\)|new\s+Array\s*\(\s*1e[89]/gi, name: 'memory_exhaust' },
      { regex: /\*\s*\d{9,}|range\s*\(\s*\d{9,}/gi, name: 'large_allocation' },
      
      // Disk filling
      { regex: /\/dev\/zero|\/dev\/urandom.*>\s*\//gi, name: 'disk_fill' },
    ]
  },

  // ═══════════════════════════════════════════════════════════════
  // CATEGORY 12: SUPPLY CHAIN (HIGH)
  // ═══════════════════════════════════════════════════════════════
  supply_chain: {
    severity: 'HIGH',
    description: 'Supply chain attack indicators',
    patterns: [
      // Typosquatting indicators
      { regex: /require\s*\(\s*['"](?!@)[a-z]+-[a-z]+['"]|from\s+['"][a-z]+-[a-z]+['"]/gi, name: 'potential_typosquat' },
      
      // Suspicious package URLs
      { regex: /npm\.pkg\.github|githubusercontent.*\.tgz/gi, name: 'non_registry_package' },
      { regex: /pip\s+install.*--index-url/gi, name: 'custom_pip_index' },
      
      // Post-install scripts
      { regex: /"(pre|post)(install|publish)"\s*:/gi, name: 'install_script' },
      { regex: /setup\.py.*cmdclass|install.*command/gi, name: 'setup_command' },
      
      // Dynamic dependency loading
      { regex: /require\s*\(\s*\w+\s*\)|import\s*\(\s*\w+\s*\)/gi, name: 'dynamic_dependency' },
    ]
  }
};

/**
 * Severity weights for scoring
 */
const SEVERITY_WEIGHTS = {
  CRITICAL: 100,
  HIGH: 50,
  MEDIUM: 20,
  LOW: 5,
  INFO: 1
};

/**
 * Risk ratings based on score
 */
const RISK_RATINGS = {
  0: { rating: 'SAFE', color: '\x1b[32m', emoji: '✅', action: 'Safe to install' },
  50: { rating: 'LOW_RISK', color: '\x1b[33m', emoji: '🟡', action: 'Review before installing' },
  100: { rating: 'MEDIUM_RISK', color: '\x1b[33m', emoji: '🟠', action: 'Careful review required' },
  200: { rating: 'HIGH_RISK', color: '\x1b[31m', emoji: '🔴', action: 'Not recommended' },
  300: { rating: 'CRITICAL_RISK', color: '\x1b[31m', emoji: '⛔', action: 'DO NOT INSTALL' }
};

/**
 * Scan code for all threat patterns
 */
function scanCode(code, filename = 'unknown') {
  const findings = [];
  const startTime = Date.now();

  for (const [category, config] of Object.entries(THREAT_PATTERNS)) {
    for (const pattern of config.patterns) {
      try {
        const matches = code.match(pattern.regex);
        if (matches) {
          findings.push({
            category,
            patternName: pattern.name,
            severity: config.severity,
            description: config.description,
            matches: [...new Set(matches)].slice(0, 5), // Unique matches, max 5
            matchCount: matches.length,
            file: filename
          });
        }
      } catch (e) {
        // Skip invalid regex
      }
    }
  }

  const scanTime = Date.now() - startTime;
  return calculateThreatScore(findings, scanTime);
}

/**
 * Calculate threat score and rating
 */
function calculateThreatScore(findings, scanTime = 0) {
  let score = 0;
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  for (const finding of findings) {
    score += SEVERITY_WEIGHTS[finding.severity] || 0;
    severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
  }

  // Determine rating
  let ratingInfo = RISK_RATINGS[0];
  for (const [threshold, info] of Object.entries(RISK_RATINGS)) {
    if (score >= parseInt(threshold)) {
      ratingInfo = info;
    }
  }

  return {
    score,
    rating: ratingInfo.rating,
    ratingInfo,
    severityCounts,
    findings,
    scanTime,
    patternVersion: VERSION,
    totalPatterns: Object.values(THREAT_PATTERNS).reduce((sum, cat) => sum + cat.patterns.length, 0)
  };
}

/**
 * Get pattern statistics
 */
function getPatternStats() {
  const stats = {
    version: VERSION,
    categories: Object.keys(THREAT_PATTERNS).length,
    totalPatterns: 0,
    bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    byCategory: {}
  };

  for (const [category, config] of Object.entries(THREAT_PATTERNS)) {
    const count = config.patterns.length;
    stats.totalPatterns += count;
    stats.bySeverity[config.severity] += count;
    stats.byCategory[category] = {
      count,
      severity: config.severity,
      description: config.description
    };
  }

  return stats;
}

/**
 * Generate detailed report
 */
function generateReport(result, format = 'markdown') {
  if (format === 'json') {
    return JSON.stringify(result, null, 2);
  }

  let report = `# 🛡️ AgentShield Security Report\n\n`;
  report += `**Generated:** ${new Date().toISOString()}\n`;
  report += `**Pattern Version:** ${result.patternVersion}\n`;
  report += `**Patterns Checked:** ${result.totalPatterns}\n`;
  report += `**Scan Time:** ${result.scanTime}ms\n\n`;

  report += `## Summary\n\n`;
  report += `| Metric | Value |\n`;
  report += `|--------|-------|\n`;
  report += `| Risk Score | ${result.score} |\n`;
  report += `| Rating | ${result.ratingInfo.emoji} ${result.rating} |\n`;
  report += `| Recommendation | ${result.ratingInfo.action} |\n`;
  report += `| Critical Findings | ${result.severityCounts.CRITICAL} |\n`;
  report += `| High Findings | ${result.severityCounts.HIGH} |\n`;
  report += `| Medium Findings | ${result.severityCounts.MEDIUM} |\n\n`;

  if (result.findings.length > 0) {
    report += `## Findings\n\n`;
    
    // Group by severity
    const bySeverity = {};
    for (const f of result.findings) {
      if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
      bySeverity[f.severity].push(f);
    }

    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      const findings = bySeverity[severity] || [];
      if (findings.length === 0) continue;

      const icon = severity === 'CRITICAL' ? '🔴' :
                   severity === 'HIGH' ? '🟠' :
                   severity === 'MEDIUM' ? '🟡' : '🟢';

      report += `### ${icon} ${severity} (${findings.length})\n\n`;
      
      for (const f of findings) {
        report += `**${f.category}** - ${f.patternName}\n`;
        report += `- ${f.description}\n`;
        report += `- File: \`${f.file}\`\n`;
        report += `- Matches: ${f.matchCount}\n`;
        if (f.matches.length > 0) {
          report += `- Example: \`${f.matches[0].substring(0, 60)}...\`\n`;
        }
        report += `\n`;
      }
    }
  } else {
    report += `## ✅ No Threats Detected\n\n`;
    report += `This code appears to be safe. However, always review code manually before running it.\n`;
  }

  return report;
}

// CLI
if (require.main === module) {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (cmd === 'stats') {
    const stats = getPatternStats();
    console.log('\n📊 AGENTSHIELD PATTERN DATABASE V2\n');
    console.log(`Version: ${stats.version}`);
    console.log(`Categories: ${stats.categories}`);
    console.log(`Total Patterns: ${stats.totalPatterns}`);
    console.log(`\nBy Severity:`);
    for (const [sev, count] of Object.entries(stats.bySeverity)) {
      console.log(`  ${sev}: ${count}`);
    }
    console.log(`\nBy Category:`);
    for (const [cat, info] of Object.entries(stats.byCategory)) {
      console.log(`  ${cat}: ${info.count} patterns (${info.severity})`);
    }

  } else if (cmd === 'scan' && args[1]) {
    const fs = require('fs');
    const path = require('path');
    const target = args[1];

    if (!fs.existsSync(target)) {
      console.error(`File not found: ${target}`);
      process.exit(1);
    }

    const code = fs.readFileSync(target, 'utf8');
    const result = scanCode(code, target);
    console.log(generateReport(result));

  } else {
    console.log(`
AgentShield Threat Patterns V2
==============================
Usage:
  node threat-patterns-v2.js stats         Show pattern statistics
  node threat-patterns-v2.js scan <file>   Scan a file

Pattern Database: ${Object.values(THREAT_PATTERNS).reduce((sum, cat) => sum + cat.patterns.length, 0)} patterns across ${Object.keys(THREAT_PATTERNS).length} categories
    `);
  }
}

module.exports = {
  THREAT_PATTERNS,
  SEVERITY_WEIGHTS,
  RISK_RATINGS,
  scanCode,
  calculateThreatScore,
  getPatternStats,
  generateReport,
  VERSION
};
