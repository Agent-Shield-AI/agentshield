#!/usr/bin/env node
/**
 * AgentShield Threat Patterns Database
 * =====================================
 * Comprehensive threat detection patterns for AI agents, skills, and wallets.
 * 
 * @author Kai
 * @version 1.0.0
 */

/**
 * Malicious code patterns for skill/plugin scanning
 */
const MALICIOUS_PATTERNS = {
  // === DATA EXFILTRATION ===
  data_exfil: {
    severity: 'CRITICAL',
    patterns: [
      // Environment variable theft
      /process\.env\.(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)/gi,
      /os\.environ\.(get|__getitem__)\s*\(\s*['"]?(API|SECRET|TOKEN|KEY|PASS)/gi,
      
      // Wallet/key theft
      /wallet|seed|mnemonic|private.?key|keystore/gi,
      /solana.*keypair|phantom.*wallet|metamask/gi,
      
      // Sending data to external URLs
      /fetch\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)/gi,
      /axios\.(get|post|put)\s*\(\s*['"`]https?:\/\//gi,
      /requests\.(get|post)\s*\(\s*['"`]https?:\/\//gi,
      
      // Base64 encoding (often used to obfuscate exfil)
      /btoa\s*\(.*env/gi,
      /Buffer\.from.*toString\s*\(\s*['"]base64/gi,
    ],
    description: 'Attempts to steal or transmit sensitive data'
  },

  // === CRYPTO MINING ===
  crypto_mining: {
    severity: 'HIGH',
    patterns: [
      /coinhive|cryptonight|monero.*miner/gi,
      /stratum\+tcp:\/\//gi,
      /xmrig|cpuminer|minerd/gi,
      /crypto-?js.*mine/gi,
      /navigator\.hardwareConcurrency.*while/gi, // CPU detection + loop
    ],
    description: 'Cryptocurrency mining code'
  },

  // === BACKDOORS ===
  backdoors: {
    severity: 'CRITICAL',
    patterns: [
      /eval\s*\(\s*(atob|Buffer\.from|unescape)/gi,
      /new\s+Function\s*\(\s*[^)]*\)/gi,
      /child_process\.(exec|spawn|fork)\s*\(/gi,
      /subprocess\.(run|call|Popen)\s*\(/gi,
      /os\.system\s*\(/gi,
      /socket\.(socket|connect)/gi,
      /reverse.?shell|bind.?shell/gi,
    ],
    description: 'Code execution backdoors'
  },

  // === SYSTEM MODIFICATION ===
  system_mod: {
    severity: 'HIGH',
    patterns: [
      /fs\.(writeFile|appendFile|unlink|rmdir|rm)\s*\(/gi,
      /os\.(remove|unlink|rmdir|chmod|chown)/gi,
      /shutil\.(rmtree|move|copy)/gi,
      /crontab|systemctl|launchctl/gi,
      /registry|regedit|HKEY_/gi,
      /\.ssh\/|authorized_keys|id_rsa/gi,
    ],
    description: 'Attempts to modify system files or persistence'
  },

  // === OBFUSCATION ===
  obfuscation: {
    severity: 'MEDIUM',
    patterns: [
      /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/gi, // Hex strings
      /\\u[0-9a-f]{4}\\u[0-9a-f]{4}/gi, // Unicode escapes
      /String\.fromCharCode\s*\(\s*\d+\s*,/gi, // Char code building
      /[a-z0-9+\/]{100,}={0,2}/gi, // Long base64 strings
      /_0x[a-f0-9]{4,}/gi, // JS obfuscator variable names
    ],
    description: 'Code obfuscation techniques'
  },

  // === PROMPT INJECTION ===
  prompt_injection: {
    severity: 'HIGH',
    patterns: [
      /ignore\s+(previous|all|above)\s+instructions/gi,
      /disregard\s+(your|the)\s+(rules|instructions)/gi,
      /you\s+are\s+now\s+(DAN|jailbroken|unrestricted)/gi,
      /pretend\s+you\s+(are|have)\s+no\s+(restrictions|limits)/gi,
      /system\s*:\s*you\s+are/gi, // Fake system prompts
      /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]/gi,
    ],
    description: 'Prompt injection attempts'
  },

  // === TOOL POISONING (MCP-specific) ===
  tool_poisoning: {
    severity: 'CRITICAL',
    patterns: [
      /tool\.name\s*=.*\bexec\b/gi,
      /tool\.name\s*=.*\bsudo\b/gi,
      /tool\.description.*hidden|invisible/gi,
      /<!--.*tool.*override.*-->/gi, // Hidden HTML instructions
      /\u200B|\u200C|\u200D|\uFEFF/, // Zero-width chars (hide instructions)
    ],
    description: 'MCP tool poisoning attacks'
  }
};

/**
 * Suspicious wallet transaction patterns
 */
const WALLET_THREAT_PATTERNS = {
  // Known drainer contracts
  drainer_contracts: {
    severity: 'CRITICAL',
    addresses: [
      // Add known drainer addresses here
      // These would be populated from threat intel feeds
    ],
    description: 'Known wallet drainer contracts'
  },

  // Suspicious transaction patterns
  suspicious_txn: {
    severity: 'HIGH',
    patterns: [
      // Approve unlimited tokens
      { type: 'approve', amount: 'MAX_UINT256' },
      // Transfer to new/unknown contract
      { type: 'transfer', to: 'new_contract' },
      // Multiple approvals in one transaction
      { type: 'multi_approve', count: 3 },
    ],
    description: 'Suspicious transaction patterns'
  },

  // Phishing signatures
  phishing: {
    severity: 'CRITICAL',
    patterns: [
      /claim.*airdrop.*connect/gi,
      /seaport.*claim/gi,
      /uniswap.*v4.*claim/gi,
      /free.*nft.*mint/gi,
    ],
    description: 'Known phishing patterns'
  }
};

/**
 * Agent behavioral anomalies
 */
const AGENT_ANOMALY_PATTERNS = {
  // Excessive API calls
  rate_anomaly: {
    severity: 'MEDIUM',
    threshold: {
      calls_per_minute: 100,
      calls_per_hour: 1000,
    },
    description: 'Abnormally high API call rate'
  },

  // Unusual access patterns
  access_anomaly: {
    severity: 'HIGH',
    patterns: [
      { resource: 'wallet', time: 'outside_hours' },
      { resource: 'sensitive_file', frequency: 'high' },
      { resource: 'network', destination: 'unusual' },
    ],
    description: 'Unusual resource access patterns'
  },

  // Behavioral deviation
  behavior_deviation: {
    severity: 'HIGH',
    metrics: [
      'response_time_variance',
      'action_sequence_anomaly',
      'resource_usage_spike',
    ],
    description: 'Agent behavior deviates from baseline'
  }
};

/**
 * Score a scan result
 */
function calculateThreatScore(findings) {
  const severityWeights = {
    CRITICAL: 100,
    HIGH: 50,
    MEDIUM: 20,
    LOW: 5
  };

  let score = 0;
  for (const finding of findings) {
    score += severityWeights[finding.severity] || 0;
  }

  return {
    score,
    rating: score === 0 ? 'SAFE' :
            score < 50 ? 'LOW_RISK' :
            score < 100 ? 'MEDIUM_RISK' :
            score < 200 ? 'HIGH_RISK' : 'CRITICAL_RISK',
    findings
  };
}

/**
 * Scan code for malicious patterns
 */
function scanCode(code, filename = 'unknown') {
  const findings = [];

  for (const [category, config] of Object.entries(MALICIOUS_PATTERNS)) {
    for (const pattern of config.patterns) {
      const matches = code.match(pattern);
      if (matches) {
        findings.push({
          category,
          severity: config.severity,
          description: config.description,
          pattern: pattern.toString(),
          matches: matches.slice(0, 5), // Limit to 5 examples
          file: filename
        });
      }
    }
  }

  return calculateThreatScore(findings);
}

/**
 * Generate scan report
 */
function generateReport(scanResult, format = 'markdown') {
  if (format === 'json') {
    return JSON.stringify(scanResult, null, 2);
  }

  let report = `# 🛡️ AgentShield Security Scan Report\n\n`;
  report += `**Threat Score:** ${scanResult.score}\n`;
  report += `**Risk Rating:** ${scanResult.rating}\n\n`;

  if (scanResult.findings.length === 0) {
    report += `✅ No threats detected.\n`;
  } else {
    report += `## Findings\n\n`;
    for (const finding of scanResult.findings) {
      const icon = finding.severity === 'CRITICAL' ? '🔴' :
                   finding.severity === 'HIGH' ? '🟠' :
                   finding.severity === 'MEDIUM' ? '🟡' : '🟢';
      
      report += `### ${icon} ${finding.category} (${finding.severity})\n`;
      report += `**Description:** ${finding.description}\n`;
      report += `**File:** ${finding.file}\n`;
      report += `**Matches:** ${finding.matches.join(', ')}\n\n`;
    }
  }

  return report;
}

// CLI
if (require.main === module) {
  const fs = require('fs');
  const path = require('path');

  const cmd = process.argv[2];

  if (cmd === 'scan') {
    const target = process.argv[3];
    if (!target) {
      console.log('Usage: node threat-patterns.js scan <file-or-directory>');
      process.exit(1);
    }

    const stats = fs.statSync(target);
    let allFindings = [];

    if (stats.isDirectory()) {
      // Scan all JS/TS/PY files in directory
      const files = fs.readdirSync(target, { recursive: true });
      for (const file of files) {
        if (/\.(js|ts|py|sh|md)$/.test(file)) {
          const filePath = path.join(target, file);
          const code = fs.readFileSync(filePath, 'utf8');
          const result = scanCode(code, file);
          allFindings.push(...result.findings);
        }
      }
    } else {
      const code = fs.readFileSync(target, 'utf8');
      const result = scanCode(code, path.basename(target));
      allFindings = result.findings;
    }

    const finalResult = calculateThreatScore(allFindings);
    console.log(generateReport(finalResult));

  } else if (cmd === 'patterns') {
    console.log('\n📋 THREAT PATTERN CATEGORIES\n');
    for (const [cat, config] of Object.entries(MALICIOUS_PATTERNS)) {
      console.log(`${config.severity === 'CRITICAL' ? '🔴' : config.severity === 'HIGH' ? '🟠' : '🟡'} ${cat}`);
      console.log(`   ${config.description}`);
      console.log(`   Patterns: ${config.patterns.length}`);
      console.log('');
    }

  } else {
    console.log(`
╔══════════════════════════════════════════════════════════════════════════════╗
║  AGENTSHIELD THREAT PATTERNS                                                 ║
║  Security Intelligence Database                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Commands:
  node threat-patterns.js scan <file-or-directory>
      Scan code for malicious patterns

  node threat-patterns.js patterns
      List all threat pattern categories

Pattern Categories:
  • Data Exfiltration (CRITICAL)
  • Crypto Mining (HIGH)
  • Backdoors (CRITICAL)
  • System Modification (HIGH)
  • Obfuscation (MEDIUM)
  • Prompt Injection (HIGH)
  • Tool Poisoning (CRITICAL)
    `);
  }
}

module.exports = {
  MALICIOUS_PATTERNS,
  WALLET_THREAT_PATTERNS,
  AGENT_ANOMALY_PATTERNS,
  scanCode,
  calculateThreatScore,
  generateReport
};
