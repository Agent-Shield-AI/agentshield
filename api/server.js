#!/usr/bin/env node
/**
 * AgentShield API Server
 * =======================
 * REST API for the AgentShield security platform.
 * Designed to run on Vercel serverless or standalone.
 * 
 * Endpoints:
 *   POST /api/scan       - Scan code for threats
 *   GET  /api/patterns   - Get pattern statistics
 *   GET  /api/health     - Health check
 *   POST /api/verify     - Verify API key
 * 
 * @author Kai
 * @version 1.0.0
 */

const http = require('http');
const url = require('url');
const { scanCode, getPatternStats, generateReport, VERSION } = require('../core/threat-patterns-v2');

// Configuration
const PORT = process.env.PORT || 3847;
const API_KEYS = new Map(); // In production, use a database

// Rate limiting (in-memory, use Redis in production)
const rateLimits = new Map();
const RATE_LIMIT_FREE = 10; // per day
const RATE_LIMIT_PRO = 1000; // per day

/**
 * CORS headers
 */
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
  'Content-Type': 'application/json'
};

/**
 * Send JSON response
 */
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, CORS_HEADERS);
  res.end(JSON.stringify(data, null, 2));
}

/**
 * Parse JSON body
 */
async function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Get client identifier for rate limiting
 */
function getClientId(req) {
  return req.headers['x-api-key'] || 
         req.headers['x-forwarded-for'] || 
         req.socket.remoteAddress ||
         'anonymous';
}

/**
 * Check rate limit
 */
function checkRateLimit(clientId, isPro = false) {
  const now = Date.now();
  const dayStart = new Date().setHours(0, 0, 0, 0);
  const limit = isPro ? RATE_LIMIT_PRO : RATE_LIMIT_FREE;

  if (!rateLimits.has(clientId) || rateLimits.get(clientId).dayStart < dayStart) {
    rateLimits.set(clientId, { count: 0, dayStart });
  }

  const clientLimit = rateLimits.get(clientId);
  if (clientLimit.count >= limit) {
    return { allowed: false, remaining: 0, limit };
  }

  clientLimit.count++;
  return { allowed: true, remaining: limit - clientLimit.count, limit };
}

/**
 * Validate API key
 */
function validateApiKey(apiKey) {
  if (!apiKey) return { valid: false, tier: 'free' };
  
  // In production, check against database
  // For now, accept any key starting with 'ask_'
  if (apiKey.startsWith('ask_pro_')) {
    return { valid: true, tier: 'pro' };
  }
  if (apiKey.startsWith('ask_ent_')) {
    return { valid: true, tier: 'enterprise' };
  }
  
  return { valid: false, tier: 'free' };
}

/**
 * API Routes
 */
const routes = {
  // Health check
  'GET /api/health': async (req, res) => {
    sendJSON(res, 200, {
      status: 'healthy',
      version: VERSION,
      timestamp: new Date().toISOString()
    });
  },

  // Get pattern statistics
  'GET /api/patterns': async (req, res) => {
    const stats = getPatternStats();
    sendJSON(res, 200, {
      success: true,
      data: stats
    });
  },

  // Scan code for threats
  'POST /api/scan': async (req, res) => {
    const clientId = getClientId(req);
    const apiKey = req.headers['x-api-key'];
    const auth = validateApiKey(apiKey);
    const isPro = auth.tier === 'pro' || auth.tier === 'enterprise';

    // Rate limit check
    const rateLimit = checkRateLimit(clientId, isPro);
    if (!rateLimit.allowed) {
      return sendJSON(res, 429, {
        success: false,
        error: 'Rate limit exceeded',
        limit: rateLimit.limit,
        resetAt: new Date(new Date().setHours(24, 0, 0, 0)).toISOString(),
        upgrade: 'Get unlimited scans at https://agentshield.dev/pricing'
      });
    }

    try {
      const body = await parseBody(req);
      
      if (!body.code) {
        return sendJSON(res, 400, {
          success: false,
          error: 'Missing required field: code'
        });
      }

      const code = body.code;
      const filename = body.filename || 'input';
      const format = body.format || 'json';

      // Limit code size for free tier
      const maxSize = isPro ? 1000000 : 50000; // 1MB pro, 50KB free
      if (code.length > maxSize) {
        return sendJSON(res, 400, {
          success: false,
          error: `Code exceeds maximum size (${maxSize} bytes for ${auth.tier} tier)`,
          upgrade: isPro ? null : 'Upgrade for larger files: https://agentshield.dev/pricing'
        });
      }

      // Scan the code
      const result = scanCode(code, filename);

      // Build response
      const response = {
        success: true,
        data: {
          score: result.score,
          rating: result.rating,
          recommendation: result.ratingInfo.action,
          findings: result.findings.length,
          severityCounts: result.severityCounts,
          scanTime: result.scanTime,
          patternVersion: result.patternVersion,
          patternsChecked: result.totalPatterns
        },
        rateLimit: {
          remaining: rateLimit.remaining,
          limit: rateLimit.limit,
          tier: auth.tier
        }
      };

      // Include full findings for pro users
      if (isPro) {
        response.data.detailedFindings = result.findings;
      } else {
        // Free tier gets limited findings
        response.data.detailedFindings = result.findings.slice(0, 3);
        if (result.findings.length > 3) {
          response.data.moreFindings = result.findings.length - 3;
          response.data.upgradeMessage = 'Upgrade to see all findings: https://agentshield.dev/pricing';
        }
      }

      // Generate report if requested
      if (format === 'markdown') {
        response.report = generateReport(result, 'markdown');
      }

      sendJSON(res, 200, response);

    } catch (error) {
      sendJSON(res, 500, {
        success: false,
        error: error.message
      });
    }
  },

  // Verify API key
  'POST /api/verify': async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    const auth = validateApiKey(apiKey);
    
    sendJSON(res, 200, {
      success: true,
      valid: auth.valid,
      tier: auth.tier,
      limits: {
        scansPerDay: auth.tier === 'enterprise' ? 'unlimited' :
                     auth.tier === 'pro' ? RATE_LIMIT_PRO : RATE_LIMIT_FREE,
        maxCodeSize: auth.tier === 'enterprise' ? '10MB' :
                     auth.tier === 'pro' ? '1MB' : '50KB',
        features: auth.tier === 'enterprise' ? ['scan', 'monitor', 'webhook', 'custom_patterns'] :
                  auth.tier === 'pro' ? ['scan', 'monitor', 'webhook'] : ['scan']
      }
    });
  },

  // Webhook registration (Pro+)
  'POST /api/webhook': async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    const auth = validateApiKey(apiKey);
    
    if (auth.tier !== 'pro' && auth.tier !== 'enterprise') {
      return sendJSON(res, 403, {
        success: false,
        error: 'Webhooks require Pro or Enterprise tier',
        upgrade: 'https://agentshield.dev/pricing'
      });
    }

    const body = await parseBody(req);
    
    // In production, save webhook URL to database
    sendJSON(res, 200, {
      success: true,
      message: 'Webhook registered',
      webhook: {
        url: body.url,
        events: body.events || ['scan.critical', 'scan.high']
      }
    });
  }
};

/**
 * Main request handler
 */
async function handleRequest(req, res) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    return res.end();
  }

  const parsedUrl = url.parse(req.url, true);
  const routeKey = `${req.method} ${parsedUrl.pathname}`;

  // Find matching route
  const handler = routes[routeKey];
  
  if (handler) {
    try {
      await handler(req, res, parsedUrl.query);
    } catch (error) {
      console.error('Handler error:', error);
      sendJSON(res, 500, {
        success: false,
        error: 'Internal server error'
      });
    }
  } else {
    sendJSON(res, 404, {
      success: false,
      error: 'Not found',
      availableEndpoints: [
        'GET  /api/health',
        'GET  /api/patterns',
        'POST /api/scan',
        'POST /api/verify',
        'POST /api/webhook'
      ]
    });
  }
}

/**
 * Start server
 */
function startServer() {
  const server = http.createServer(handleRequest);

  server.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════════╗
║                   AGENTSHIELD API SERVER                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Status:     Running                                             ║
║  Port:       ${PORT}                                                ║
║  Version:    ${VERSION}                                              ║
║  Patterns:   ${getPatternStats().totalPatterns}                                               ║
╠══════════════════════════════════════════════════════════════════╣
║  Endpoints:                                                      ║
║    GET  /api/health     - Health check                           ║
║    GET  /api/patterns   - Pattern statistics                     ║
║    POST /api/scan       - Scan code for threats                  ║
║    POST /api/verify     - Verify API key                         ║
║    POST /api/webhook    - Register webhook (Pro+)                ║
╚══════════════════════════════════════════════════════════════════╝
    `);
  });

  return server;
}

// Start if running directly
if (require.main === module) {
  startServer();
}

// Export for serverless
module.exports = handleRequest;
module.exports.startServer = startServer;
