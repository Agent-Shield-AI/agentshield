# 🛡️ AgentShield

**The Immune System for AI Agents**

Scan AI skills, MCP servers, and plugins for malware, backdoors, and security vulnerabilities before they compromise your systems.

[![npm version](https://badge.fury.io/js/agentshield.svg)](https://www.npmjs.com/package/agentshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚨 The Problem

- **33% of MCP servers have critical vulnerabilities** (Enkrypt AI, 2025)
- **Prompt injection is #1 threat** in OWASP LLM Top 10
- **Tool poisoning attacks** can hijack your AI agents
- **No standardized security scanning** for AI skills

## ✅ The Solution

AgentShield provides:

- **Skill Scanner** - Detect malware, spyware, and backdoors in code
- **Agent Guardian** - Real-time monitoring with kill switch
- **Wallet Sentinel** - Transaction screening for crypto
- **Behavioral Analysis** - Detect anomalous agent behavior

---

## 🚀 Quick Start

### Installation

```bash
npm install -g agentshield
```

### Scan a Skill

```bash
agentshield scan ./my-skill-folder
```

### Output Example

```
═══════════════════════════════════════════════════════════════════
  📊 SCAN RESULTS
═══════════════════════════════════════════════════════════════════
  Files Scanned:    12
  Scan Time:        847ms
  Threats Found:    3
  Risk Score:       150
  Rating:           HIGH_RISK
═══════════════════════════════════════════════════════════════════

🚨 FINDINGS:

🔴 CRITICAL (1)
   └─ data_exfil: Attempts to steal or transmit sensitive data
      File: index.js
      Match: "process.env.API_KEY"

🟠 HIGH (2)
   └─ backdoors: Code execution backdoors
      File: utils.js
      Match: "eval(atob..."
```

---

## 📖 Commands

### Scan Skills/Plugins

```bash
# Basic scan
agentshield scan ./path/to/skill

# JSON output
agentshield scan ./skill --json

# Save report
agentshield scan ./skill --json --output report.json
```

### Monitor Agents

```bash
# Start monitoring
agentshield monitor my-trading-bot

# With custom limits
agentshield monitor bot --rate-limit 30 --spend-limit 0.05
```

### Check Transactions

```bash
# Analyze a transaction
agentshield wallet 0x1234...5678 0.5

# With origin check
agentshield wallet 0x1234... 0.5 --origin https://suspicious-site.com
```

### View Patterns

```bash
agentshield patterns
```

---

## 🔍 Threat Categories

| Category | Severity | Description |
|----------|----------|-------------|
| Data Exfiltration | CRITICAL | Stealing secrets, API keys, wallet seeds |
| Backdoors | CRITICAL | Code execution, reverse shells |
| Tool Poisoning | CRITICAL | MCP tool hijacking attacks |
| Prompt Injection | HIGH | LLM manipulation attempts |
| Crypto Mining | HIGH | Unauthorized cryptocurrency mining |
| System Modification | HIGH | Modifying system files, persistence |
| Obfuscation | MEDIUM | Suspicious code hiding techniques |

---

## 🖥️ Web Interface

AgentShield includes a web-based scanner:

```bash
# Serve the web interface
npx serve web

# Or use the hosted version at
https://agentshield.dev
```

---

## 🔧 API Usage

```javascript
const { scanCode, generateReport } = require('agentshield/core/threat-patterns');
const { AgentGuardian } = require('agentshield/core/agent-guardian');
const { WalletSentinel } = require('agentshield/core/wallet-sentinel');

// Scan code
const result = scanCode(codeString, 'filename.js');
console.log(result.rating); // 'SAFE', 'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL_RISK'

// Monitor an agent
const guardian = new AgentGuardian({ maxActionsPerMinute: 60 });
guardian.registerAgent('my-bot', { name: 'Trading Bot' });
guardian.start();

// Screen transactions
const sentinel = new WalletSentinel({ maxSingleTxn: 0.5 });
const analysis = await sentinel.analyzeTxn({ to: '0x...', value: 0.1 });
```

---

## 🏗️ Architecture

```
agentshield/
├── cli/
│   └── agentshield.js    # Unified CLI
├── core/
│   ├── threat-patterns.js   # Pattern detection engine
│   ├── agent-guardian.js    # Real-time monitoring
│   └── wallet-sentinel.js   # Transaction screening
├── web/
│   └── index.html           # Web interface
└── package.json
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding New Patterns

Patterns are defined in `core/threat-patterns.js`:

```javascript
MALICIOUS_PATTERNS.new_category = {
  severity: 'HIGH',
  patterns: [
    /your-regex-here/gi,
  ],
  description: 'Description of what this detects'
};
```

---

## 📊 Stats

- **7** threat categories
- **50+** detection patterns
- **< 3s** average scan time
- **0** dependencies (core scanner)

---

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

## 🔗 Links

- **Website:** https://agentshield.dev
- **Documentation:** https://docs.agentshield.dev
- **GitHub:** https://github.com/agentshield/agentshield
- **NPM:** https://www.npmjs.com/package/agentshield
- **Twitter:** @agentshield

---

**Built with ❤️ for the AI agent ecosystem**

*Protecting autonomous agents, one scan at a time.*
