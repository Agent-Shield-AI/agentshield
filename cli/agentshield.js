#!/usr/bin/env node
/**
 * AgentShield CLI
 * ================
 * Unified command-line interface for all AgentShield security tools.
 * 
 * Usage:
 *   agentshield scan <path>        Scan a skill/plugin for threats
 *   agentshield monitor <agent>    Start monitoring an agent
 *   agentshield wallet <txn>       Analyze a transaction
 *   agentshield report             Generate security report
 * 
 * @author Kai
 * @version 1.0.0
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');

// Import our core modules
const { scanCode, generateReport, MALICIOUS_PATTERNS } = require('../core/threat-patterns');
const { AgentGuardian, DeadManSwitch } = require('../core/agent-guardian');
const { WalletSentinel, formatAnalysis } = require('../core/wallet-sentinel');

const VERSION = '1.0.0';
const BANNER = `
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║     █████╗  ██████╗ ███████╗███╗   ██╗████████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ║
║    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗║
║    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗███████║██║█████╗  ██║     ██║  ██║║
║    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║║
║    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝║
║    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ║
║                                                                           ║
║                    The Immune System for AI Agents                        ║
║                           v${VERSION}                                         ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
`;

/**
 * Scan a skill/plugin directory for threats
 */
async function scanSkill(targetPath, options = {}) {
  console.log(`\n🔍 Scanning: ${targetPath}\n`);

  if (!fs.existsSync(targetPath)) {
    console.error(`❌ Path not found: ${targetPath}`);
    process.exit(1);
  }

  const stats = fs.statSync(targetPath);
  const allFindings = [];
  const filesScanned = [];
  const startTime = Date.now();

  // Scan patterns
  const scanPatterns = ['.js', '.ts', '.py', '.sh', '.md', '.json', '.yml', '.yaml'];

  if (stats.isDirectory()) {
    // Recursively scan directory
    const walkDir = (dir) => {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        
        if (stat.isDirectory()) {
          // Skip node_modules, .git, etc.
          if (!['node_modules', '.git', '__pycache__', 'venv'].includes(file)) {
            walkDir(filePath);
          }
        } else if (scanPatterns.some(ext => file.endsWith(ext))) {
          try {
            const code = fs.readFileSync(filePath, 'utf8');
            const result = scanCode(code, filePath);
            allFindings.push(...result.findings);
            filesScanned.push(filePath);
          } catch (e) {
            // Skip files that can't be read
          }
        }
      }
    };
    walkDir(targetPath);
  } else {
    const code = fs.readFileSync(targetPath, 'utf8');
    const result = scanCode(code, targetPath);
    allFindings.push(...result.findings);
    filesScanned.push(targetPath);
  }

  const scanTime = Date.now() - startTime;

  // Calculate overall score
  const severityWeights = { CRITICAL: 100, HIGH: 50, MEDIUM: 20, LOW: 5 };
  let totalScore = 0;
  for (const finding of allFindings) {
    totalScore += severityWeights[finding.severity] || 0;
  }

  const rating = totalScore === 0 ? 'SAFE' :
                 totalScore < 50 ? 'LOW_RISK' :
                 totalScore < 100 ? 'MEDIUM_RISK' :
                 totalScore < 200 ? 'HIGH_RISK' : 'CRITICAL_RISK';

  const ratingColors = {
    SAFE: '\x1b[32m', // Green
    LOW_RISK: '\x1b[33m', // Yellow
    MEDIUM_RISK: '\x1b[33m',
    HIGH_RISK: '\x1b[31m', // Red
    CRITICAL_RISK: '\x1b[31m'
  };

  // Print results
  console.log('═'.repeat(70));
  console.log(`  📊 SCAN RESULTS`);
  console.log('═'.repeat(70));
  console.log(`  Files Scanned:    ${filesScanned.length}`);
  console.log(`  Scan Time:        ${scanTime}ms`);
  console.log(`  Threats Found:    ${allFindings.length}`);
  console.log(`  Risk Score:       ${totalScore}`);
  console.log(`  Rating:           ${ratingColors[rating]}${rating}\x1b[0m`);
  console.log('═'.repeat(70));

  if (allFindings.length > 0) {
    console.log('\n🚨 FINDINGS:\n');

    // Group by severity
    const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    for (const finding of allFindings) {
      bySeverity[finding.severity]?.push(finding);
    }

    for (const [severity, findings] of Object.entries(bySeverity)) {
      if (findings.length === 0) continue;

      const icon = severity === 'CRITICAL' ? '🔴' :
                   severity === 'HIGH' ? '🟠' :
                   severity === 'MEDIUM' ? '🟡' : '🟢';

      console.log(`${icon} ${severity} (${findings.length})`);
      for (const f of findings.slice(0, 5)) { // Limit to 5 per category
        console.log(`   └─ ${f.category}: ${f.description}`);
        console.log(`      File: ${f.file}`);
        if (f.matches && f.matches.length > 0) {
          console.log(`      Match: "${f.matches[0].substring(0, 50)}..."`);
        }
      }
      if (findings.length > 5) {
        console.log(`   └─ ... and ${findings.length - 5} more`);
      }
      console.log('');
    }
  } else {
    console.log('\n✅ No threats detected!\n');
  }

  // Recommendation
  console.log('─'.repeat(70));
  if (rating === 'SAFE') {
    console.log('✅ RECOMMENDATION: Safe to install');
  } else if (rating === 'LOW_RISK') {
    console.log('⚠️  RECOMMENDATION: Review findings before installing');
  } else if (rating === 'MEDIUM_RISK') {
    console.log('⚠️  RECOMMENDATION: Careful review required');
  } else {
    console.log('🚫 RECOMMENDATION: DO NOT INSTALL - Critical security issues');
  }
  console.log('─'.repeat(70));

  // Output JSON if requested
  if (options.json) {
    const jsonOutput = {
      target: targetPath,
      timestamp: new Date().toISOString(),
      filesScanned: filesScanned.length,
      scanTimeMs: scanTime,
      score: totalScore,
      rating,
      findings: allFindings
    };
    
    if (options.output) {
      fs.writeFileSync(options.output, JSON.stringify(jsonOutput, null, 2));
      console.log(`\n📄 JSON report saved to: ${options.output}`);
    } else {
      console.log('\n' + JSON.stringify(jsonOutput, null, 2));
    }
  }

  return { score: totalScore, rating, findings: allFindings };
}

/**
 * Start agent monitoring
 */
function startMonitor(agentId, options = {}) {
  console.log(`\n🛡️ Starting Agent Guardian for: ${agentId}\n`);

  const guardian = new AgentGuardian({
    maxActionsPerMinute: options.rateLimit || 60,
    maxSpendPerAction: options.spendLimit || 0.1,
    heartbeatInterval: options.heartbeat || 60000
  });

  guardian.registerAgent(agentId, {
    name: options.name || agentId,
    startedAt: new Date().toISOString()
  });

  guardian.on('alert', (alert) => {
    console.log(`\n⚠️  ALERT: [${alert.type}] ${alert.message}`);
  });

  guardian.on('agent:killed', ({ agentId, reason }) => {
    console.log(`\n🔴 KILLED: ${agentId} - ${reason}`);
  });

  guardian.start();

  console.log('Guardian is now monitoring. Press Ctrl+C to stop.\n');
  console.log('Commands:');
  console.log('  status    - Show agent status');
  console.log('  alerts    - Show recent alerts');
  console.log('  kill      - Trigger kill switch');
  console.log('  exit      - Stop monitoring\n');

  // Simple REPL for demo
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'guardian> '
  });

  rl.prompt();
  rl.on('line', (line) => {
    const cmd = line.trim().toLowerCase();
    
    switch (cmd) {
      case 'status':
        console.log(JSON.stringify(guardian.getStatus(agentId), null, 2));
        break;
      case 'alerts':
        console.log(JSON.stringify(guardian.getAlerts(10), null, 2));
        break;
      case 'kill':
        guardian.killSwitch(agentId, 'Manual kill switch activated');
        break;
      case 'exit':
      case 'quit':
        guardian.stop();
        rl.close();
        process.exit(0);
        break;
      default:
        console.log('Unknown command');
    }
    
    rl.prompt();
  });
}

/**
 * Check wallet transaction
 */
async function checkWallet(to, value, options = {}) {
  console.log('\n🔍 Analyzing transaction...\n');

  const sentinel = new WalletSentinel({
    maxSingleTxn: options.limit || 1.0,
    maxDailySpend: options.daily || 5.0
  });

  const txn = {
    to,
    value: parseFloat(value) || 0,
    data: options.data || '0x',
    origin: options.origin || ''
  };

  const analysis = await sentinel.analyzeTxn(txn);
  console.log(formatAnalysis(analysis));

  return analysis;
}

/**
 * Show patterns info
 */
function showPatterns() {
  console.log('\n📋 THREAT PATTERN DATABASE\n');
  
  for (const [category, config] of Object.entries(MALICIOUS_PATTERNS)) {
    const icon = config.severity === 'CRITICAL' ? '🔴' :
                 config.severity === 'HIGH' ? '🟠' :
                 config.severity === 'MEDIUM' ? '🟡' : '🟢';
    
    console.log(`${icon} ${category.toUpperCase()} (${config.severity})`);
    console.log(`   ${config.description}`);
    console.log(`   Patterns: ${config.patterns.length}`);
    console.log('');
  }
}

/**
 * Main CLI entry point
 */
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(BANNER);
    console.log(`
COMMANDS:

  scan <path> [options]     Scan a skill/plugin for security threats
    --json                  Output results as JSON
    --output <file>         Save report to file

  monitor <agent-id>        Start real-time agent monitoring
    --rate-limit <n>        Max actions per minute (default: 60)
    --spend-limit <n>       Max spend per action (default: 0.1)
    --heartbeat <ms>        Heartbeat interval (default: 60000)

  wallet <to> <value>       Analyze a wallet transaction
    --limit <n>             Max transaction value (default: 1.0)
    --daily <n>             Max daily spend (default: 5.0)
    --data <hex>            Transaction data
    --origin <url>          Origin domain

  patterns                  Show all threat patterns

  version                   Show version

EXAMPLES:

  agentshield scan ./my-skill
  agentshield scan ./skill --json --output report.json
  agentshield monitor trading-bot-1
  agentshield wallet 0x1234...5678 0.5
  agentshield patterns

DOCUMENTATION:
  https://github.com/agentshield/agentshield

    `);
    return;
  }

  switch (command) {
    case 'scan':
      const scanPath = args[1];
      if (!scanPath) {
        console.error('❌ Please provide a path to scan');
        process.exit(1);
      }
      await scanSkill(scanPath, {
        json: args.includes('--json'),
        output: args[args.indexOf('--output') + 1]
      });
      break;

    case 'monitor':
      const agentId = args[1] || 'default-agent';
      startMonitor(agentId, {
        rateLimit: parseInt(args[args.indexOf('--rate-limit') + 1]) || 60,
        spendLimit: parseFloat(args[args.indexOf('--spend-limit') + 1]) || 0.1,
        heartbeat: parseInt(args[args.indexOf('--heartbeat') + 1]) || 60000
      });
      break;

    case 'wallet':
      const to = args[1];
      const value = args[2];
      if (!to) {
        console.error('❌ Please provide a destination address');
        process.exit(1);
      }
      await checkWallet(to, value, {
        limit: parseFloat(args[args.indexOf('--limit') + 1]) || 1.0,
        daily: parseFloat(args[args.indexOf('--daily') + 1]) || 5.0,
        data: args[args.indexOf('--data') + 1],
        origin: args[args.indexOf('--origin') + 1]
      });
      break;

    case 'patterns':
      showPatterns();
      break;

    case 'version':
    case '-v':
    case '--version':
      console.log(`AgentShield v${VERSION}`);
      break;

    default:
      console.error(`❌ Unknown command: ${command}`);
      console.log('Run "agentshield help" for usage');
      process.exit(1);
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
