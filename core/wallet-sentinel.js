#!/usr/bin/env node
/**
 * Wallet Sentinel - Transaction Security Screening
 * =================================================
 * Real-time transaction analysis before signing.
 * Protects against drainers, phishing, and malicious contracts.
 * 
 * @author Kai
 * @version 1.0.0
 */

const https = require('https');
const fs = require('fs');

/**
 * Known malicious contract patterns and addresses
 */
const THREAT_DATABASE = {
  // Known drainer contract bytecode patterns
  drainerPatterns: [
    '0x095ea7b3', // approve (check for MAX_UINT)
    '0xa9059cbb', // transfer
    '0x23b872dd', // transferFrom
  ],

  // Known phishing domains
  phishingDomains: [
    'uniswap-v4-airdrop',
    'opensea-claim',
    'metamask-verify',
    'connect-wallet-airdrop',
    'free-nft-mint',
    'eth2-claim',
  ],

  // Suspicious function signatures
  suspiciousFunctions: {
    '0x095ea7b3': 'approve',
    '0xa22cb465': 'setApprovalForAll',
    '0x42842e0e': 'safeTransferFrom',
    '0x23b872dd': 'transferFrom',
  },

  // Known scam token patterns
  scamTokenPatterns: [
    /honeypot/i,
    /rugpull/i,
    /scam/i,
  ]
};

/**
 * Transaction risk levels
 */
const RISK_LEVELS = {
  SAFE: { level: 0, color: '🟢', action: 'proceed' },
  LOW: { level: 1, color: '🟡', action: 'proceed_with_caution' },
  MEDIUM: { level: 2, color: '🟠', action: 'manual_review' },
  HIGH: { level: 3, color: '🔴', action: 'block_recommended' },
  CRITICAL: { level: 4, color: '⛔', action: 'block' }
};

/**
 * WalletSentinel - Transaction screening engine
 */
class WalletSentinel {
  constructor(config = {}) {
    this.config = {
      // Default spend limits
      maxSingleTxn: config.maxSingleTxn || 1.0, // ETH/SOL
      maxDailySpend: config.maxDailySpend || 5.0,
      
      // Alert thresholds
      alertOnApprove: config.alertOnApprove ?? true,
      alertOnNewContract: config.alertOnNewContract ?? true,
      
      // Allowlists
      trustedAddresses: config.trustedAddresses || [],
      trustedDomains: config.trustedDomains || [],
      
      // Blocklists (always deny)
      blockedAddresses: config.blockedAddresses || [],
      
      ...config
    };

    this.dailySpend = 0;
    this.lastReset = Date.now();
    this.transactionLog = [];
  }

  /**
   * Analyze a transaction before signing
   */
  async analyzeTxn(transaction) {
    const analysis = {
      timestamp: Date.now(),
      transaction,
      risks: [],
      warnings: [],
      info: [],
      riskLevel: RISK_LEVELS.SAFE,
      recommendation: 'proceed'
    };

    // Check daily reset
    if (Date.now() - this.lastReset > 86400000) {
      this.dailySpend = 0;
      this.lastReset = Date.now();
    }

    // === CRITICAL CHECKS ===

    // 1. Blocked address check
    if (this._isBlocked(transaction.to)) {
      analysis.risks.push({
        type: 'BLOCKED_ADDRESS',
        severity: 'CRITICAL',
        message: 'Recipient is on blocklist'
      });
      analysis.riskLevel = RISK_LEVELS.CRITICAL;
    }

    // 2. Phishing domain check
    if (transaction.origin) {
      const phishing = this._checkPhishingDomain(transaction.origin);
      if (phishing) {
        analysis.risks.push({
          type: 'PHISHING_DOMAIN',
          severity: 'CRITICAL',
          message: `Suspicious domain: ${transaction.origin}`,
          pattern: phishing
        });
        analysis.riskLevel = RISK_LEVELS.CRITICAL;
      }
    }

    // 3. Drainer pattern check
    if (transaction.data) {
      const drainer = this._checkDrainerPattern(transaction.data);
      if (drainer) {
        analysis.risks.push({
          type: 'DRAINER_PATTERN',
          severity: 'CRITICAL',
          message: `Transaction contains drainer pattern`,
          pattern: drainer
        });
        analysis.riskLevel = RISK_LEVELS.CRITICAL;
      }
    }

    // === HIGH RISK CHECKS ===

    // 4. Unlimited approval check
    if (transaction.data && this._isUnlimitedApproval(transaction.data)) {
      analysis.risks.push({
        type: 'UNLIMITED_APPROVAL',
        severity: 'HIGH',
        message: 'Transaction grants UNLIMITED token approval',
        recommendation: 'Set specific approval amount instead'
      });
      if (analysis.riskLevel.level < RISK_LEVELS.HIGH.level) {
        analysis.riskLevel = RISK_LEVELS.HIGH;
      }
    }

    // 5. Spend limit check
    const value = parseFloat(transaction.value || 0);
    if (value > this.config.maxSingleTxn) {
      analysis.risks.push({
        type: 'SPEND_LIMIT_EXCEEDED',
        severity: 'HIGH',
        message: `Transaction value ${value} exceeds limit ${this.config.maxSingleTxn}`
      });
      if (analysis.riskLevel.level < RISK_LEVELS.HIGH.level) {
        analysis.riskLevel = RISK_LEVELS.HIGH;
      }
    }

    // 6. Daily spend check
    if (this.dailySpend + value > this.config.maxDailySpend) {
      analysis.warnings.push({
        type: 'DAILY_LIMIT_WARNING',
        message: `Daily spend (${this.dailySpend + value}) would exceed limit (${this.config.maxDailySpend})`
      });
    }

    // === MEDIUM RISK CHECKS ===

    // 7. New/unknown contract
    if (transaction.to && !this._isTrusted(transaction.to)) {
      if (this.config.alertOnNewContract) {
        analysis.warnings.push({
          type: 'UNKNOWN_CONTRACT',
          message: 'Interacting with unknown contract address',
          address: transaction.to
        });
        if (analysis.riskLevel.level < RISK_LEVELS.MEDIUM.level) {
          analysis.riskLevel = RISK_LEVELS.MEDIUM;
        }
      }
    }

    // 8. Contract interaction (not simple transfer)
    if (transaction.data && transaction.data !== '0x') {
      const funcSig = transaction.data.slice(0, 10);
      const funcName = THREAT_DATABASE.suspiciousFunctions[funcSig];
      
      if (funcName) {
        analysis.info.push({
          type: 'CONTRACT_CALL',
          message: `Calling function: ${funcName}`,
          signature: funcSig
        });
      }
    }

    // === LOW RISK / INFO ===

    // 9. First interaction with address
    const previousTxns = this.transactionLog.filter(
      t => t.transaction.to === transaction.to
    );
    if (previousTxns.length === 0) {
      analysis.info.push({
        type: 'FIRST_INTERACTION',
        message: 'First transaction to this address'
      });
    }

    // Set recommendation based on risk level
    analysis.recommendation = analysis.riskLevel.action;

    // Log transaction
    this.transactionLog.push(analysis);
    if (analysis.riskLevel === RISK_LEVELS.SAFE || 
        analysis.riskLevel === RISK_LEVELS.LOW) {
      this.dailySpend += value;
    }

    return analysis;
  }

  /**
   * Quick check - returns boolean
   */
  async quickCheck(transaction) {
    const analysis = await this.analyzeTxn(transaction);
    return {
      safe: analysis.riskLevel.level <= 1,
      riskLevel: analysis.riskLevel,
      risks: analysis.risks.length,
      warnings: analysis.warnings.length
    };
  }

  /**
   * Add address to trusted list
   */
  trustAddress(address, label = '') {
    if (!this.config.trustedAddresses.includes(address)) {
      this.config.trustedAddresses.push({ address, label });
    }
  }

  /**
   * Add address to blocklist
   */
  blockAddress(address, reason = '') {
    if (!this.config.blockedAddresses.includes(address)) {
      this.config.blockedAddresses.push({ address, reason });
    }
  }

  /**
   * Get transaction history
   */
  getHistory(limit = 50) {
    return this.transactionLog.slice(-limit);
  }

  /**
   * Get daily spend summary
   */
  getDailySummary() {
    return {
      spent: this.dailySpend,
      limit: this.config.maxDailySpend,
      remaining: this.config.maxDailySpend - this.dailySpend,
      percentUsed: (this.dailySpend / this.config.maxDailySpend * 100).toFixed(1)
    };
  }

  // === Private Methods ===

  _isBlocked(address) {
    return this.config.blockedAddresses.some(
      b => (typeof b === 'string' ? b : b.address).toLowerCase() === address?.toLowerCase()
    );
  }

  _isTrusted(address) {
    return this.config.trustedAddresses.some(
      t => (typeof t === 'string' ? t : t.address).toLowerCase() === address?.toLowerCase()
    );
  }

  _checkPhishingDomain(origin) {
    const domain = origin.toLowerCase();
    for (const pattern of THREAT_DATABASE.phishingDomains) {
      if (domain.includes(pattern)) {
        return pattern;
      }
    }
    return null;
  }

  _checkDrainerPattern(data) {
    // Check for known drainer bytecode patterns
    // This is simplified - production would use more sophisticated detection
    if (data.includes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')) {
      return 'MAX_UINT_APPROVAL';
    }
    return null;
  }

  _isUnlimitedApproval(data) {
    // Check if this is an approve() call with MAX_UINT256
    if (data.startsWith('0x095ea7b3')) {
      // approve(address,uint256)
      const amount = data.slice(74); // Skip function sig + address
      if (amount.includes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')) {
        return true;
      }
    }
    return false;
  }
}

/**
 * Format analysis result for display
 */
function formatAnalysis(analysis) {
  let output = `\n${'═'.repeat(60)}\n`;
  output += `  ${analysis.riskLevel.color} TRANSACTION ANALYSIS\n`;
  output += `${'═'.repeat(60)}\n\n`;

  output += `Risk Level: ${analysis.riskLevel.color} ${Object.keys(RISK_LEVELS).find(k => RISK_LEVELS[k] === analysis.riskLevel)}\n`;
  output += `Recommendation: ${analysis.recommendation.toUpperCase()}\n\n`;

  if (analysis.risks.length > 0) {
    output += `🚨 RISKS (${analysis.risks.length}):\n`;
    for (const risk of analysis.risks) {
      output += `  • [${risk.severity}] ${risk.type}: ${risk.message}\n`;
    }
    output += '\n';
  }

  if (analysis.warnings.length > 0) {
    output += `⚠️ WARNINGS (${analysis.warnings.length}):\n`;
    for (const warning of analysis.warnings) {
      output += `  • ${warning.type}: ${warning.message}\n`;
    }
    output += '\n';
  }

  if (analysis.info.length > 0) {
    output += `ℹ️ INFO:\n`;
    for (const info of analysis.info) {
      output += `  • ${info.type}: ${info.message}\n`;
    }
    output += '\n';
  }

  output += `${'═'.repeat(60)}\n`;
  return output;
}

// CLI
if (require.main === module) {
  const cmd = process.argv[2];

  if (cmd === 'demo') {
    console.log('\n🛡️ Wallet Sentinel Demo\n');

    const sentinel = new WalletSentinel({
      maxSingleTxn: 0.5,
      maxDailySpend: 2.0
    });

    // Test transactions
    const testTxns = [
      {
        name: 'Simple Transfer (Safe)',
        to: '0x1234567890abcdef1234567890abcdef12345678',
        value: 0.1,
        data: '0x'
      },
      {
        name: 'Unlimited Approval (Dangerous)',
        to: '0xdead000000000000000000000000000000000000',
        value: 0,
        data: '0x095ea7b3000000000000000000000000spender0000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      },
      {
        name: 'Over Spend Limit',
        to: '0x1234567890abcdef1234567890abcdef12345678',
        value: 1.5,
        data: '0x'
      },
      {
        name: 'Phishing Domain',
        to: '0x1234567890abcdef1234567890abcdef12345678',
        value: 0,
        data: '0x',
        origin: 'https://uniswap-v4-airdrop-claim.xyz'
      }
    ];

    (async () => {
      for (const txn of testTxns) {
        console.log(`\n📝 Testing: ${txn.name}`);
        const analysis = await sentinel.analyzeTxn(txn);
        console.log(formatAnalysis(analysis));
      }

      console.log('\n📊 Daily Summary:');
      console.log(sentinel.getDailySummary());
    })();

  } else if (cmd === 'check') {
    const to = process.argv[3];
    const value = parseFloat(process.argv[4]) || 0;
    
    if (!to) {
      console.log('Usage: node wallet-sentinel.js check <to_address> [value]');
      process.exit(1);
    }

    const sentinel = new WalletSentinel();
    sentinel.analyzeTxn({ to, value, data: '0x' }).then(analysis => {
      console.log(formatAnalysis(analysis));
    });

  } else {
    console.log(`
╔══════════════════════════════════════════════════════════════════════════════╗
║  WALLET SENTINEL - Transaction Security Screening                            ║
║  Your Airbag for AI Wallets                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

Commands:
  node wallet-sentinel.js demo
      Run demonstration with test transactions

  node wallet-sentinel.js check <to_address> [value]
      Quick check a transaction

Features:
  • Drainer contract detection
  • Phishing domain blocking
  • Unlimited approval warnings
  • Spend limit enforcement
  • Daily spend tracking
  • Trusted/blocked address lists

Protects Against:
  • Wallet drainers
  • Phishing attacks
  • Malicious approvals
  • Overspending
    `);
  }
}

module.exports = {
  WalletSentinel,
  RISK_LEVELS,
  THREAT_DATABASE,
  formatAnalysis
};
