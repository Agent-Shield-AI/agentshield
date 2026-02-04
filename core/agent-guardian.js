#!/usr/bin/env node
/**
 * Agent Guardian - Real-Time Agent Monitoring
 * ============================================
 * Monitor autonomous AI agents for anomalies, enforce limits,
 * and implement kill switches when things go wrong.
 * 
 * Sci-Fi Inspired: Like having Jarvis watch over your robots
 * 
 * @author Kai
 * @version 1.0.0
 */

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

/**
 * Agent Guardian - Monitors agent behavior in real-time
 */
class AgentGuardian extends EventEmitter {
  constructor(config = {}) {
    super();
    
    this.config = {
      // Rate limits
      maxActionsPerMinute: config.maxActionsPerMinute || 60,
      maxActionsPerHour: config.maxActionsPerHour || 500,
      
      // Spend limits (for wallet-connected agents)
      maxSpendPerAction: config.maxSpendPerAction || 0.1, // SOL/ETH
      maxSpendPerDay: config.maxSpendPerDay || 1.0,
      
      // Dead man's switch
      heartbeatInterval: config.heartbeatInterval || 60000, // 1 minute
      maxMissedHeartbeats: config.maxMissedHeartbeats || 3,
      
      // Behavioral baseline
      baselineLearningPeriod: config.baselineLearningPeriod || 86400000, // 24 hours
      anomalyThreshold: config.anomalyThreshold || 2.0, // Standard deviations
      
      // Logging
      logDir: config.logDir || './agent-logs',
      ...config
    };

    this.agents = new Map(); // agentId -> AgentState
    this.alerts = [];
    this.isRunning = false;
  }

  /**
   * Register an agent for monitoring
   */
  registerAgent(agentId, metadata = {}) {
    const state = {
      id: agentId,
      metadata,
      registeredAt: Date.now(),
      lastHeartbeat: Date.now(),
      missedHeartbeats: 0,
      actions: [],
      spendToday: 0,
      behavioral: {
        baseline: null,
        samples: [],
        isLearning: true
      },
      status: 'active',
      alerts: []
    };

    this.agents.set(agentId, state);
    this.emit('agent:registered', { agentId, metadata });
    
    console.log(`🛡️ Agent registered: ${agentId}`);
    return state;
  }

  /**
   * Record an agent action
   */
  recordAction(agentId, action) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      console.warn(`Unknown agent: ${agentId}`);
      return { allowed: false, reason: 'Agent not registered' };
    }

    // Check if agent is suspended
    if (agent.status === 'suspended') {
      return { allowed: false, reason: 'Agent is suspended' };
    }

    // Rate limit check
    const rateLimitResult = this._checkRateLimit(agent);
    if (!rateLimitResult.allowed) {
      this._raiseAlert(agentId, 'RATE_LIMIT', rateLimitResult.reason);
      return rateLimitResult;
    }

    // Spend limit check (if applicable)
    if (action.spend) {
      const spendResult = this._checkSpendLimit(agent, action.spend);
      if (!spendResult.allowed) {
        this._raiseAlert(agentId, 'SPEND_LIMIT', spendResult.reason);
        return spendResult;
      }
      agent.spendToday += action.spend;
    }

    // Record action
    agent.actions.push({
      ...action,
      timestamp: Date.now()
    });

    // Behavioral analysis (if baseline exists)
    if (agent.behavioral.baseline) {
      const anomalyResult = this._checkBehavioralAnomaly(agent, action);
      if (anomalyResult.isAnomaly) {
        this._raiseAlert(agentId, 'BEHAVIORAL_ANOMALY', anomalyResult.reason);
      }
    } else {
      // Still learning baseline
      agent.behavioral.samples.push(action);
    }

    // Update heartbeat
    agent.lastHeartbeat = Date.now();
    agent.missedHeartbeats = 0;

    this.emit('agent:action', { agentId, action });
    return { allowed: true };
  }

  /**
   * Heartbeat - agent must call this periodically
   */
  heartbeat(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) return { success: false, reason: 'Unknown agent' };

    agent.lastHeartbeat = Date.now();
    agent.missedHeartbeats = 0;

    this.emit('agent:heartbeat', { agentId });
    return { success: true };
  }

  /**
   * Start the guardian monitoring loop
   */
  start() {
    if (this.isRunning) return;
    this.isRunning = true;

    console.log('🛡️ Agent Guardian started');

    // Heartbeat monitor
    this._heartbeatInterval = setInterval(() => {
      this._checkHeartbeats();
    }, this.config.heartbeatInterval);

    // Daily reset
    this._dailyResetInterval = setInterval(() => {
      this._dailyReset();
    }, 86400000);

    // Baseline learning check
    this._baselineInterval = setInterval(() => {
      this._updateBaselines();
    }, 3600000); // Every hour

    this.emit('guardian:started');
  }

  /**
   * Stop the guardian
   */
  stop() {
    this.isRunning = false;
    clearInterval(this._heartbeatInterval);
    clearInterval(this._dailyResetInterval);
    clearInterval(this._baselineInterval);
    
    console.log('🛡️ Agent Guardian stopped');
    this.emit('guardian:stopped');
  }

  /**
   * KILL SWITCH - Immediately suspend an agent
   */
  killSwitch(agentId, reason = 'Manual kill switch') {
    const agent = this.agents.get(agentId);
    if (!agent) return { success: false, reason: 'Unknown agent' };

    agent.status = 'suspended';
    agent.suspendedAt = Date.now();
    agent.suspendReason = reason;

    this._raiseAlert(agentId, 'KILL_SWITCH', reason);
    this.emit('agent:killed', { agentId, reason });

    console.log(`🔴 KILL SWITCH activated for ${agentId}: ${reason}`);
    return { success: true };
  }

  /**
   * Reactivate a suspended agent
   */
  reactivate(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) return { success: false, reason: 'Unknown agent' };

    agent.status = 'active';
    agent.reactivatedAt = Date.now();

    this.emit('agent:reactivated', { agentId });
    console.log(`🟢 Agent reactivated: ${agentId}`);
    return { success: true };
  }

  /**
   * Get agent status
   */
  getStatus(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) return null;

    const now = Date.now();
    const actionsLastMinute = agent.actions.filter(
      a => a.timestamp > now - 60000
    ).length;
    const actionsLastHour = agent.actions.filter(
      a => a.timestamp > now - 3600000
    ).length;

    return {
      id: agent.id,
      status: agent.status,
      uptime: now - agent.registeredAt,
      lastHeartbeat: agent.lastHeartbeat,
      missedHeartbeats: agent.missedHeartbeats,
      actionsLastMinute,
      actionsLastHour,
      spendToday: agent.spendToday,
      alerts: agent.alerts.slice(-10),
      isLearning: agent.behavioral.isLearning
    };
  }

  /**
   * Get all alerts
   */
  getAlerts(limit = 50) {
    return this.alerts.slice(-limit);
  }

  // === Private Methods ===

  _checkRateLimit(agent) {
    const now = Date.now();
    const actionsLastMinute = agent.actions.filter(
      a => a.timestamp > now - 60000
    ).length;
    const actionsLastHour = agent.actions.filter(
      a => a.timestamp > now - 3600000
    ).length;

    if (actionsLastMinute >= this.config.maxActionsPerMinute) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: ${actionsLastMinute}/${this.config.maxActionsPerMinute} per minute`
      };
    }

    if (actionsLastHour >= this.config.maxActionsPerHour) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: ${actionsLastHour}/${this.config.maxActionsPerHour} per hour`
      };
    }

    return { allowed: true };
  }

  _checkSpendLimit(agent, amount) {
    if (amount > this.config.maxSpendPerAction) {
      return {
        allowed: false,
        reason: `Spend ${amount} exceeds per-action limit ${this.config.maxSpendPerAction}`
      };
    }

    if (agent.spendToday + amount > this.config.maxSpendPerDay) {
      return {
        allowed: false,
        reason: `Daily spend limit would be exceeded`
      };
    }

    return { allowed: true };
  }

  _checkBehavioralAnomaly(agent, action) {
    // Simplified anomaly detection
    // In production, this would use ML models
    
    const baseline = agent.behavioral.baseline;
    if (!baseline) return { isAnomaly: false };

    // Check action frequency anomaly
    const currentRate = agent.actions.filter(
      a => a.timestamp > Date.now() - 60000
    ).length;

    if (baseline.avgActionsPerMinute > 0) {
      const zScore = (currentRate - baseline.avgActionsPerMinute) / 
                     (baseline.stdActionsPerMinute || 1);
      
      if (Math.abs(zScore) > this.config.anomalyThreshold) {
        return {
          isAnomaly: true,
          reason: `Action rate anomaly: ${currentRate}/min vs baseline ${baseline.avgActionsPerMinute}/min`
        };
      }
    }

    return { isAnomaly: false };
  }

  _checkHeartbeats() {
    const now = Date.now();

    for (const [agentId, agent] of this.agents) {
      if (agent.status === 'suspended') continue;

      const timeSinceHeartbeat = now - agent.lastHeartbeat;
      
      if (timeSinceHeartbeat > this.config.heartbeatInterval) {
        agent.missedHeartbeats++;
        
        this._raiseAlert(agentId, 'MISSED_HEARTBEAT', 
          `Missed heartbeat #${agent.missedHeartbeats}`);

        if (agent.missedHeartbeats >= this.config.maxMissedHeartbeats) {
          this.killSwitch(agentId, 
            `Dead man's switch: ${agent.missedHeartbeats} missed heartbeats`);
        }
      }
    }
  }

  _dailyReset() {
    for (const agent of this.agents.values()) {
      agent.spendToday = 0;
      // Trim old actions (keep last 24 hours)
      const cutoff = Date.now() - 86400000;
      agent.actions = agent.actions.filter(a => a.timestamp > cutoff);
    }
    console.log('🛡️ Daily reset completed');
  }

  _updateBaselines() {
    for (const agent of this.agents.values()) {
      if (!agent.behavioral.isLearning) continue;

      const learningTime = Date.now() - agent.registeredAt;
      if (learningTime < this.config.baselineLearningPeriod) continue;

      // Calculate baseline from samples
      const samples = agent.behavioral.samples;
      if (samples.length < 100) continue; // Need enough data

      // Calculate average actions per minute
      const now = Date.now();
      const minuteBuckets = {};
      
      for (const action of agent.actions) {
        const minute = Math.floor(action.timestamp / 60000);
        minuteBuckets[minute] = (minuteBuckets[minute] || 0) + 1;
      }

      const counts = Object.values(minuteBuckets);
      const avg = counts.reduce((a, b) => a + b, 0) / counts.length;
      const variance = counts.reduce((sum, c) => sum + Math.pow(c - avg, 2), 0) / counts.length;
      const std = Math.sqrt(variance);

      agent.behavioral.baseline = {
        avgActionsPerMinute: avg,
        stdActionsPerMinute: std,
        calculatedAt: now
      };

      agent.behavioral.isLearning = false;
      console.log(`🛡️ Baseline calculated for ${agent.id}`);
    }
  }

  _raiseAlert(agentId, type, message) {
    const alert = {
      agentId,
      type,
      message,
      timestamp: Date.now()
    };

    this.alerts.push(alert);
    
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.alerts.push(alert);
    }

    this.emit('alert', alert);
    console.log(`⚠️ ALERT [${agentId}] ${type}: ${message}`);
  }
}

/**
 * Dead Man's Switch - Standalone implementation
 */
class DeadManSwitch {
  constructor(options = {}) {
    this.interval = options.interval || 60000;
    this.maxMissed = options.maxMissed || 3;
    this.onTrigger = options.onTrigger || (() => {});
    
    this.lastPing = Date.now();
    this.missedCount = 0;
    this.isArmed = false;
    this._timer = null;
  }

  arm() {
    this.isArmed = true;
    this.lastPing = Date.now();
    this.missedCount = 0;
    
    this._timer = setInterval(() => {
      if (!this.isArmed) return;
      
      const elapsed = Date.now() - this.lastPing;
      if (elapsed > this.interval) {
        this.missedCount++;
        console.log(`⏰ Dead Man's Switch: Missed ping #${this.missedCount}`);
        
        if (this.missedCount >= this.maxMissed) {
          console.log(`🔴 Dead Man's Switch TRIGGERED!`);
          this.onTrigger();
          this.disarm();
        }
      }
    }, this.interval);

    console.log(`🛡️ Dead Man's Switch armed (${this.interval}ms interval)`);
  }

  ping() {
    this.lastPing = Date.now();
    this.missedCount = 0;
  }

  disarm() {
    this.isArmed = false;
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    console.log(`🛡️ Dead Man's Switch disarmed`);
  }
}

// CLI
if (require.main === module) {
  const cmd = process.argv[2];

  if (cmd === 'demo') {
    console.log('\n🛡️ Agent Guardian Demo\n');
    
    const guardian = new AgentGuardian({
      maxActionsPerMinute: 10,
      heartbeatInterval: 5000,
      maxMissedHeartbeats: 2
    });

    // Register test agent
    guardian.registerAgent('test-agent-1', {
      name: 'Test Trading Bot',
      type: 'trading'
    });

    // Set up event listeners
    guardian.on('alert', (alert) => {
      console.log(`📢 Event: ${JSON.stringify(alert)}`);
    });

    guardian.on('agent:killed', ({ agentId, reason }) => {
      console.log(`💀 Agent killed: ${agentId} - ${reason}`);
    });

    // Start guardian
    guardian.start();

    // Simulate some actions
    let actionCount = 0;
    const actionInterval = setInterval(() => {
      actionCount++;
      const result = guardian.recordAction('test-agent-1', {
        type: 'trade',
        details: `Action #${actionCount}`
      });
      console.log(`Action ${actionCount}: ${result.allowed ? '✅' : '❌ ' + result.reason}`);
      
      if (actionCount >= 15) {
        clearInterval(actionInterval);
        console.log('\n📊 Final Status:');
        console.log(JSON.stringify(guardian.getStatus('test-agent-1'), null, 2));
        
        setTimeout(() => {
          guardian.stop();
          process.exit(0);
        }, 2000);
      }
    }, 500);

  } else {
    console.log(`
╔══════════════════════════════════════════════════════════════════════════════╗
║  AGENT GUARDIAN - Real-Time Agent Monitoring                                 ║
║  The Immune System for Autonomous AI                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

Commands:
  node agent-guardian.js demo
      Run interactive demonstration

Features:
  • Rate limiting (actions per minute/hour)
  • Spend limits (per action/per day)
  • Dead man's switch (heartbeat monitoring)
  • Behavioral anomaly detection
  • Real-time alerts
  • Kill switch for emergencies

Use Cases:
  • Trading bots
  • Autonomous agents with wallet access
  • Any AI that needs guardrails
    `);
  }
}

module.exports = {
  AgentGuardian,
  DeadManSwitch
};
