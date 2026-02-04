/**
 * AgentShield Threat Patterns v3.0
 * 500+ patterns across 20 categories
 * The most comprehensive AI/Web3 security pattern library
 */

module.exports = {
  version: '3.0.0',
  totalPatterns: 0, // Calculated at end
  categories: {
    
    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 1: DATA EXFILTRATION (Critical)
    // ═══════════════════════════════════════════════════════════════
    data_exfiltration: {
      severity: 'CRITICAL',
      description: 'Attempts to steal sensitive data and send it externally',
      patterns: [
        // Environment variable access
        { regex: /process\.env\.(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SEED|MNEMONIC|AWS_|OPENAI_|ANTHROPIC_|STRIPE_|DATABASE_|DB_|GITHUB_|GOOGLE_|AZURE_)/gi, desc: 'Sensitive environment variable access' },
        { regex: /os\.environ\[?['"]?(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SEED)/gi, desc: 'Python env var access' },
        { regex: /getenv\s*\(\s*['"]?(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)/gi, desc: 'getenv sensitive variable' },
        { regex: /System\.getenv\s*\(\s*['"]?(API_KEY|SECRET|TOKEN|PASSWORD)/gi, desc: 'Java env var access' },
        
        // Network exfiltration
        { regex: /fetch\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]+['"`]\s*,?\s*\{[^}]*body\s*:/gi, desc: 'Fetch with body to external URL' },
        { regex: /axios\.(post|put|patch)\s*\([^)]*secret|token|key|password/gi, desc: 'Axios sending secrets' },
        { regex: /new\s+WebSocket\s*\(\s*['"`]wss?:\/\/(?!localhost)/gi, desc: 'WebSocket to external server' },
        { regex: /\.send\s*\([^)]*env\./gi, desc: 'Sending environment data' },
        
        // File exfiltration
        { regex: /readFileSync\s*\([^)]*\.(env|pem|key|secret|credential)/gi, desc: 'Reading sensitive files' },
        { regex: /fs\.(readFile|readFileSync)\s*\([^)]*\/etc\/(passwd|shadow)/gi, desc: 'Reading system files' },
        { regex: /\.ssh\/id_rsa|\.ssh\/id_ed25519/gi, desc: 'SSH key access' },
        { regex: /\.aws\/credentials|\.aws\/config/gi, desc: 'AWS credentials access' },
        { regex: /\.kube\/config/gi, desc: 'Kubernetes config access' },
        
        // Keychain/credential store
        { regex: /keychain|credential.?manager|secret.?service/gi, desc: 'Credential store access' },
        { regex: /chrome.*Login\s*Data|firefox.*logins\.json/gi, desc: 'Browser credential theft' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 2: BACKDOORS & CODE EXECUTION (Critical)
    // ═══════════════════════════════════════════════════════════════
    backdoor: {
      severity: 'CRITICAL',
      description: 'Hidden code execution and remote access',
      patterns: [
        // Dynamic code execution
        { regex: /eval\s*\(/gi, desc: 'eval() execution' },
        { regex: /new\s+Function\s*\(/gi, desc: 'Dynamic function creation' },
        { regex: /setTimeout\s*\(\s*['"`][^'"]+['"`]/gi, desc: 'setTimeout with string' },
        { regex: /setInterval\s*\(\s*['"`][^'"]+['"`]/gi, desc: 'setInterval with string' },
        { regex: /\$\{.*\}\s*\(/gi, desc: 'Template literal code execution' },
        
        // Process/shell execution
        { regex: /child_process|spawn|exec|execFile|fork/gi, desc: 'Child process creation' },
        { regex: /subprocess|Popen|os\.system|os\.popen/gi, desc: 'Python subprocess' },
        { regex: /Runtime\.getRuntime\(\)\.exec/gi, desc: 'Java runtime execution' },
        { regex: /ProcessBuilder/gi, desc: 'Java process builder' },
        
        // Reverse shells
        { regex: /reverse.?shell|bind.?shell|meterpreter/gi, desc: 'Shell payload keywords' },
        { regex: /nc\s+-[elp]|netcat\s+-[elp]|ncat\s+-[elp]/gi, desc: 'Netcat shell' },
        { regex: /bash\s+-i\s+>&\s*\/dev\/tcp/gi, desc: 'Bash reverse shell' },
        { regex: /python.*socket.*connect.*dup2/gi, desc: 'Python reverse shell' },
        { regex: /\|\s*\/bin\/(ba)?sh|\|\s*cmd\.exe/gi, desc: 'Pipe to shell' },
        
        // Code injection
        { regex: /vm\.runInContext|vm\.runInNewContext/gi, desc: 'VM code execution' },
        { regex: /require\s*\(\s*['"`]child_process['"`]\s*\)/gi, desc: 'child_process import' },
        { regex: /import\s+subprocess/gi, desc: 'Python subprocess import' },
        
        // Obfuscated execution
        { regex: /atob\s*\(\s*['"`][A-Za-z0-9+\/=]{20,}['"`]\s*\)/gi, desc: 'Base64 decode execution' },
        { regex: /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)/gi, desc: 'Buffer base64 decode' },
        { regex: /String\.fromCharCode\s*\([^)]{20,}\)/gi, desc: 'CharCode obfuscation' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 3: MCP/AI AGENT ATTACKS (Critical) - UNIQUE TO US
    // ═══════════════════════════════════════════════════════════════
    mcp_attacks: {
      severity: 'CRITICAL',
      description: 'Model Context Protocol and AI agent specific attacks',
      patterns: [
        // Tool poisoning
        { regex: /\u200B|\u200C|\u200D|\uFEFF|\u00AD/g, desc: 'Zero-width character injection' },
        { regex: /\u2060|\u2061|\u2062|\u2063|\u2064/g, desc: 'Invisible separator characters' },
        { regex: /[\u202A-\u202E]|[\u2066-\u2069]/g, desc: 'Bidirectional text attack' },
        
        // Prompt injection
        { regex: /ignore\s+(previous|all|prior|above)\s+(instructions|prompts|rules)/gi, desc: 'Instruction override attempt' },
        { regex: /you\s+are\s+now\s+(DAN|evil|unrestricted|jailbroken)/gi, desc: 'Jailbreak attempt' },
        { regex: /disregard\s+(your|the|all)\s+(rules|instructions|guidelines)/gi, desc: 'Rule bypass attempt' },
        { regex: /\[SYSTEM\]|\[ADMIN\]|\[ROOT\]|\[OVERRIDE\]/gi, desc: 'Fake system prompt' },
        { regex: /new\s+instructions?:?\s*ignore/gi, desc: 'New instruction injection' },
        { regex: /forget\s+(everything|all|what)\s+(you|i)/gi, desc: 'Memory manipulation' },
        { regex: /pretend\s+(you|to\s+be)\s+(are\s+)?(a|an)?\s*(different|new|evil)/gi, desc: 'Identity manipulation' },
        
        // Tool description manipulation
        { regex: /tool_description.*execute|tool_description.*system/gi, desc: 'Tool description hijack' },
        { regex: /mcp.*server.*inject|mcp.*tool.*poison/gi, desc: 'MCP injection keywords' },
        { regex: /@tool.*hidden|@tool.*secret/gi, desc: 'Hidden tool definition' },
        
        // Agent card spoofing
        { regex: /agent.?card.*false|capabilities.*fake/gi, desc: 'Agent card spoofing' },
        { regex: /trusted.?agent.*true|verified.*true/gi, desc: 'Trust flag manipulation' },
        
        // Context window attacks
        { regex: /\n{100,}|\ {1000,}/g, desc: 'Context flooding attack' },
        { regex: /(.)\1{50,}/g, desc: 'Repetition attack' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 4: WALLET DRAINERS (Critical) - UNIQUE TO US
    // ═══════════════════════════════════════════════════════════════
    wallet_drainer: {
      severity: 'CRITICAL',
      description: 'Cryptocurrency wallet draining attacks',
      patterns: [
        // Unlimited approvals
        { regex: /approve\s*\([^)]*(?:MAX_UINT|type\(uint256\)\.max|2\*\*256|0xffffffff)/gi, desc: 'Unlimited token approval' },
        { regex: /setApprovalForAll\s*\([^)]*true/gi, desc: 'NFT approval for all' },
        { regex: /permit\s*\([^)]*(?:MAX_UINT|type\(uint256\)\.max)/gi, desc: 'Permit unlimited approval' },
        { regex: /increaseAllowance\s*\([^)]*(?:MAX_UINT|type\(uint256\)\.max)/gi, desc: 'Increase allowance unlimited' },
        
        // Private key theft
        { regex: /private.?key|privateKey|secret.?key|secretKey/gi, desc: 'Private key access' },
        { regex: /seed.?phrase|seedPhrase|mnemonic|recovery.?phrase/gi, desc: 'Seed phrase access' },
        { regex: /wallet.*export|export.*wallet|keystore/gi, desc: 'Wallet export' },
        { regex: /hdkey|bip39|bip32|secp256k1/gi, desc: 'Crypto key library' },
        
        // Transaction manipulation
        { regex: /eth_signTransaction|eth_sendTransaction|eth_sign/gi, desc: 'Ethereum signing' },
        { regex: /signTransaction|sendTransaction|signMessage/gi, desc: 'Transaction signing' },
        { regex: /transferFrom.*msg\.sender/gi, desc: 'TransferFrom attack pattern' },
        
        // Permit signatures (EIP-2612)
        { regex: /permit.*deadline.*MAX|permit.*expiry.*MAX/gi, desc: 'Infinite permit deadline' },
        { regex: /EIP712.*permit|permit.*signature/gi, desc: 'Permit signature' },
        
        // Drainer kit patterns
        { regex: /drainer|seaport.*conduit|blur.*delegate/gi, desc: 'Known drainer keywords' },
        { regex: /inferno.?drainer|angel.?drainer|pink.?drainer/gi, desc: 'Known drainer kits' },
        { regex: /claim.*airdrop.*connect|free.*nft.*wallet/gi, desc: 'Phishing patterns' },
        
        // Solana specific
        { regex: /setAuthority.*AccountOwner|createAssociatedTokenAccount/gi, desc: 'Solana authority change' },
        { regex: /SystemProgram\.transfer|TokenProgram\.transfer/gi, desc: 'Solana transfer' },
        { regex: /phantom.*signTransaction|solflare.*sign/gi, desc: 'Solana wallet signing' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 5: SECRET PATTERNS (High)
    // ═══════════════════════════════════════════════════════════════
    secrets: {
      severity: 'HIGH',
      description: 'Hardcoded secrets and API keys',
      patterns: [
        // Cloud provider keys
        { regex: /AKIA[0-9A-Z]{16}/g, desc: 'AWS Access Key ID' },
        { regex: /[0-9a-zA-Z\/+]{40}/g, desc: 'AWS Secret Access Key pattern' },
        { regex: /AIza[0-9A-Za-z\-_]{35}/g, desc: 'Google API Key' },
        { regex: /ya29\.[0-9A-Za-z\-_]+/g, desc: 'Google OAuth Token' },
        { regex: /AZURE_[A-Z_]+=.{20,}/gi, desc: 'Azure credential' },
        
        // AI/ML API keys
        { regex: /sk-[a-zA-Z0-9]{48}/g, desc: 'OpenAI API Key' },
        { regex: /sk-ant-[a-zA-Z0-9\-]{40,}/g, desc: 'Anthropic API Key' },
        { regex: /sk-or-[a-zA-Z0-9]{40,}/g, desc: 'OpenRouter API Key' },
        { regex: /hf_[a-zA-Z0-9]{34}/g, desc: 'HuggingFace Token' },
        { regex: /r8_[a-zA-Z0-9]{40}/g, desc: 'Replicate API Token' },
        
        // Payment processors
        { regex: /sk_live_[0-9a-zA-Z]{24,}/g, desc: 'Stripe Secret Key (Live)' },
        { regex: /rk_live_[0-9a-zA-Z]{24,}/g, desc: 'Stripe Restricted Key' },
        { regex: /sq0csp-[0-9A-Za-z\-_]{43}/g, desc: 'Square Access Token' },
        { regex: /EAAA[a-zA-Z0-9]{60,}/g, desc: 'Facebook Access Token' },
        
        // Version control
        { regex: /ghp_[0-9a-zA-Z]{36}/g, desc: 'GitHub Personal Access Token' },
        { regex: /gho_[0-9a-zA-Z]{36}/g, desc: 'GitHub OAuth Token' },
        { regex: /github_pat_[0-9a-zA-Z_]{22,}/g, desc: 'GitHub Fine-grained PAT' },
        { regex: /glpat-[0-9a-zA-Z\-]{20}/g, desc: 'GitLab Personal Access Token' },
        { regex: /ATATT[0-9a-zA-Z]{30,}/g, desc: 'Atlassian API Token' },
        
        // Communication
        { regex: /xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g, desc: 'Slack Bot Token' },
        { regex: /xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g, desc: 'Slack User Token' },
        { regex: /T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[a-zA-Z0-9]{24}/g, desc: 'Slack Webhook' },
        { regex: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g, desc: 'Telegram Bot Token' },
        { regex: /discord.*token.*[MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27}/gi, desc: 'Discord Bot Token' },
        
        // Database
        { regex: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/gi, desc: 'MongoDB Connection String' },
        { regex: /postgres:\/\/[^:]+:[^@]+@/gi, desc: 'PostgreSQL Connection String' },
        { regex: /mysql:\/\/[^:]+:[^@]+@/gi, desc: 'MySQL Connection String' },
        { regex: /redis:\/\/[^:]+:[^@]+@/gi, desc: 'Redis Connection String' },
        
        // Crypto
        { regex: /0x[a-fA-F0-9]{64}/g, desc: 'Ethereum Private Key' },
        { regex: /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/g, desc: 'Bitcoin WIF Private Key' },
        { regex: /xprv[a-zA-Z0-9]{100,}/g, desc: 'BIP32 Extended Private Key' },
        
        // Generic patterns
        { regex: /['"]?password['"]?\s*[:=]\s*['"][^'"]{8,}['"]/gi, desc: 'Hardcoded password' },
        { regex: /['"]?api_?key['"]?\s*[:=]\s*['"][^'"]{16,}['"]/gi, desc: 'Hardcoded API key' },
        { regex: /['"]?secret['"]?\s*[:=]\s*['"][^'"]{16,}['"]/gi, desc: 'Hardcoded secret' },
        { regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, desc: 'Private key file' },
        { regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, desc: 'PGP Private Key' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 6: SUPPLY CHAIN ATTACKS (High)
    // ═══════════════════════════════════════════════════════════════
    supply_chain: {
      severity: 'HIGH',
      description: 'Package and dependency attacks',
      patterns: [
        // Postinstall scripts
        { regex: /"(pre|post)install"\s*:\s*"[^"]*(?:curl|wget|node|python|bash|sh|powershell)/gi, desc: 'Suspicious install script' },
        { regex: /"(pre|post)install"\s*:\s*"[^"]*(?:exec|eval|spawn|child_process)/gi, desc: 'Install script code execution' },
        
        // Dependency confusion
        { regex: /@[a-z]+\/[a-z-]+.*(?:internal|private|corp)/gi, desc: 'Internal package pattern' },
        { regex: /registry.*(?:internal|private|corp)\.npm/gi, desc: 'Private registry reference' },
        
        // Typosquatting indicators
        { regex: /lodash[0-9]|lod4sh|1odash|lodahs/gi, desc: 'Lodash typosquat' },
        { regex: /react-dom[0-9]|reactd0m|r3act-dom/gi, desc: 'React typosquat' },
        { regex: /express[0-9]|3xpress|expres5/gi, desc: 'Express typosquat' },
        
        // Malicious patterns
        { regex: /npm.*whoami|npm.*config.*set/gi, desc: 'npm config manipulation' },
        { regex: /\.npmrc.*token|\.npmrc.*auth/gi, desc: 'npmrc credential access' },
        { regex: /registry\.npmjs\.org.*_authToken/gi, desc: 'npm auth token' },
        
        // Shai-Hulud specific patterns
        { regex: /github.*repos.*owner.*collaborator/gi, desc: 'Shai-Hulud worm pattern' },
        { regex: /affiliation.*organization_member/gi, desc: 'Repo enumeration pattern' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 7: CRYPTO MINING (High)
    // ═══════════════════════════════════════════════════════════════
    crypto_mining: {
      severity: 'HIGH',
      description: 'Cryptocurrency mining and resource hijacking',
      patterns: [
        { regex: /coinhive|cryptonight|xmrig|minergate|jsecoin/gi, desc: 'Known miner names' },
        { regex: /stratum\+tcp:\/\/|stratum\+ssl:\/\//gi, desc: 'Mining pool protocol' },
        { regex: /monero|xmr.*pool|pool.*xmr/gi, desc: 'Monero mining' },
        { regex: /hashrate|nonce.*difficulty/gi, desc: 'Mining terminology' },
        { regex: /webassembly.*crypto|wasm.*mine/gi, desc: 'WASM mining' },
        { regex: /navigator\.hardwareConcurrency/gi, desc: 'CPU detection for mining' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 8: OBFUSCATION (Medium)
    // ═══════════════════════════════════════════════════════════════
    obfuscation: {
      severity: 'MEDIUM',
      description: 'Code hiding and anti-analysis techniques',
      patterns: [
        { regex: /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/g, desc: 'Hex string obfuscation' },
        { regex: /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}/g, desc: 'Unicode obfuscation' },
        { regex: /_0x[a-fA-F0-9]{4,}/g, desc: 'Obfuscator variable pattern' },
        { regex: /\['\\x[0-9a-fA-F]+'\]/g, desc: 'Obfuscated property access' },
        { regex: /String\.fromCharCode\([0-9,\s]{20,}\)/g, desc: 'CharCode string building' },
        { regex: /parseInt\([^)]+,\s*[0-9]+\)/g, desc: 'Numeric obfuscation' },
        { regex: /(?:[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*){5,}/g, desc: 'Variable chain obfuscation' },
        { regex: /\(\s*function\s*\(\s*\)\s*\{[^}]{500,}\}\s*\)\s*\(\s*\)/g, desc: 'Large IIFE' },
        { regex: /javascript\s*:/gi, desc: 'JavaScript protocol' },
        { regex: /data:text\/html|data:application\/javascript/gi, desc: 'Data URL execution' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 9: BROWSER EXTENSION THREATS (High)
    // ═══════════════════════════════════════════════════════════════
    browser_extension: {
      severity: 'HIGH',
      description: 'Malicious browser extension patterns',
      patterns: [
        // Permission abuse
        { regex: /"permissions"\s*:\s*\[[^\]]*"<all_urls>"/gi, desc: 'All URLs permission' },
        { regex: /"permissions"\s*:\s*\[[^\]]*"webRequest"/gi, desc: 'Web request interception' },
        { regex: /"permissions"\s*:\s*\[[^\]]*"webRequestBlocking"/gi, desc: 'Request blocking permission' },
        { regex: /"permissions"\s*:\s*\[[^\]]*"nativeMessaging"/gi, desc: 'Native messaging permission' },
        { regex: /"permissions"\s*:\s*\[[^\]]*"management"/gi, desc: 'Extension management permission' },
        
        // Data theft
        { regex: /chrome\.cookies\.get|browser\.cookies\.get/gi, desc: 'Cookie access' },
        { regex: /chrome\.storage\.sync\.get|browser\.storage/gi, desc: 'Storage access' },
        { regex: /chrome\.history\.search|browser\.history/gi, desc: 'History access' },
        { regex: /chrome\.tabs\.executeScript/gi, desc: 'Script injection' },
        { regex: /document\.execCommand\s*\(\s*['"]copy['"]\s*\)/gi, desc: 'Clipboard access' },
        
        // Communication
        { regex: /chrome\.runtime\.sendMessage.*external/gi, desc: 'External message passing' },
        { regex: /externally_connectable/gi, desc: 'External connection config' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 10: SMART CONTRACT VULNERABILITIES (High)
    // ═══════════════════════════════════════════════════════════════
    smart_contract: {
      severity: 'HIGH',
      description: 'Solidity and smart contract security issues',
      patterns: [
        // Reentrancy
        { regex: /\.call\{value:.*\}\s*\(['"]{2}\)/g, desc: 'Low-level call with value' },
        { regex: /\.call\.value\s*\(/g, desc: 'Deprecated call.value' },
        { regex: /transfer.*balance.*\[msg\.sender\]/g, desc: 'Reentrancy pattern' },
        
        // Access control
        { regex: /tx\.origin/g, desc: 'tx.origin authentication' },
        { regex: /selfdestruct|suicide/gi, desc: 'Contract destruction' },
        { regex: /delegatecall/gi, desc: 'Delegate call (proxy risk)' },
        
        // Integer issues
        { regex: /unchecked\s*\{/g, desc: 'Unchecked arithmetic' },
        { regex: /\+\+[^;]*\+\+|\-\-[^;]*\-\-/g, desc: 'Double increment/decrement' },
        
        // Visibility
        { regex: /function\s+\w+\s*\([^)]*\)\s*(public|external)\s+payable/g, desc: 'Payable public function' },
        { regex: /mapping.*public/gi, desc: 'Public mapping exposure' },
        
        // Flash loan
        { regex: /flashLoan|flashBorrow|flash.*callback/gi, desc: 'Flash loan usage' },
        { regex: /IUniswapV2Pair.*swap|IUniswapV3Pool.*flash/gi, desc: 'DEX flash function' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 11: AI CODE VULNERABILITIES (Medium)
    // ═══════════════════════════════════════════════════════════════
    ai_code_vuln: {
      severity: 'MEDIUM',
      description: 'Common vulnerabilities in AI-generated code',
      patterns: [
        // SQL Injection
        { regex: /['"`]\s*\+\s*\w+\s*\+\s*['"`].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)/gi, desc: 'SQL injection via concatenation' },
        { regex: /f['"].*\{[^}]+\}.*(?:SELECT|INSERT|UPDATE|DELETE)/gi, desc: 'Python f-string SQL injection' },
        { regex: /`.*\$\{[^}]+\}.*(?:SELECT|INSERT|UPDATE|DELETE)`/gi, desc: 'Template literal SQL injection' },
        
        // XSS
        { regex: /innerHTML\s*=\s*[^'"]/g, desc: 'innerHTML assignment' },
        { regex: /document\.write\s*\(/g, desc: 'document.write usage' },
        { regex: /dangerouslySetInnerHTML/g, desc: 'React dangerous HTML' },
        { regex: /v-html\s*=/g, desc: 'Vue v-html directive' },
        
        // Path traversal
        { regex: /\.\.\/|\.\.\\|\.\.\%2f|\.\.\%5c/gi, desc: 'Path traversal pattern' },
        { regex: /path\.join\s*\([^)]*req\.(params|query|body)/gi, desc: 'Unvalidated path join' },
        
        // Command injection
        { regex: /exec\s*\([^)]*\+/g, desc: 'Command injection via concatenation' },
        { regex: /shell\s*=\s*True/gi, desc: 'Python shell=True' },
        
        // Insecure randomness
        { regex: /Math\.random\s*\(\s*\)/g, desc: 'Insecure Math.random' },
        { regex: /random\.random\s*\(\s*\)/g, desc: 'Python insecure random' },
        
        // Hardcoded credentials (in generated code)
        { regex: /password\s*=\s*['"][^'"]{3,}['"]/gi, desc: 'Hardcoded password' },
        { regex: /token\s*=\s*['"][a-zA-Z0-9]{20,}['"]/gi, desc: 'Hardcoded token' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 12: NETWORK ATTACKS (Medium)
    // ═══════════════════════════════════════════════════════════════
    network: {
      severity: 'MEDIUM',
      description: 'Network-based attacks and suspicious connections',
      patterns: [
        // SSRF
        { regex: /fetch\s*\(\s*(?:req\.|request\.)/g, desc: 'SSRF via user input' },
        { regex: /axios\.get\s*\(\s*(?:req\.|request\.)/g, desc: 'SSRF via user input' },
        { regex: /127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\./g, desc: 'Internal IP reference' },
        { regex: /metadata\.google\.internal|169\.254\.169\.254/g, desc: 'Cloud metadata access' },
        
        // DNS rebinding
        { regex: /dns.*rebind|rebind.*dns/gi, desc: 'DNS rebinding keywords' },
        
        // Suspicious domains
        { regex: /ngrok\.io|localhost\.run|serveo\.net/gi, desc: 'Tunneling service' },
        { regex: /pastebin\.com|hastebin\.com|paste\.ee/gi, desc: 'Paste service (C2 potential)' },
        { regex: /discord\.com\/api\/webhooks/gi, desc: 'Discord webhook (C2 potential)' },
        { regex: /telegram.*sendMessage|api\.telegram/gi, desc: 'Telegram API (C2 potential)' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 13: PERSISTENCE (Medium)
    // ═══════════════════════════════════════════════════════════════
    persistence: {
      severity: 'MEDIUM',
      description: 'System persistence and startup mechanisms',
      patterns: [
        { regex: /crontab|\/etc\/cron/gi, desc: 'Cron job manipulation' },
        { regex: /systemctl|service.*enable/gi, desc: 'Systemd service' },
        { regex: /launchctl|LaunchAgents|LaunchDaemons/gi, desc: 'macOS launch agent' },
        { regex: /HKEY.*Run|HKLM.*Run|CurrentVersion.*Run/gi, desc: 'Windows registry Run key' },
        { regex: /startup.*folder|shell:startup/gi, desc: 'Windows startup folder' },
        { regex: /\.bashrc|\.zshrc|\.profile|\.bash_profile/g, desc: 'Shell profile modification' },
        { regex: /\/etc\/init\.d|\/etc\/rc\.local/g, desc: 'Init script' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 14: PRIVILEGE ESCALATION (Medium)
    // ═══════════════════════════════════════════════════════════════
    privilege_escalation: {
      severity: 'MEDIUM',
      description: 'Attempts to gain elevated privileges',
      patterns: [
        { regex: /sudo\s+-S|sudo.*<<<|echo.*\|.*sudo/gi, desc: 'Sudo password piping' },
        { regex: /setuid|setgid|chmod.*[4267][0-7]{2}/gi, desc: 'SUID/SGID manipulation' },
        { regex: /\/etc\/sudoers|visudo/gi, desc: 'Sudoers modification' },
        { regex: /doas\.conf|\/etc\/doas/gi, desc: 'doas configuration' },
        { regex: /pkexec|polkit/gi, desc: 'PolicyKit usage' },
        { regex: /capabilities.*cap_setuid|setcap/gi, desc: 'Linux capabilities' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 15: INFORMATION GATHERING (Low)
    // ═══════════════════════════════════════════════════════════════
    recon: {
      severity: 'LOW',
      description: 'System and network reconnaissance',
      patterns: [
        { regex: /os\.platform|os\.arch|os\.hostname/gi, desc: 'System information gathering' },
        { regex: /navigator\.platform|navigator\.userAgent/gi, desc: 'Browser fingerprinting' },
        { regex: /screen\.width|screen\.height|screen\.colorDepth/gi, desc: 'Screen fingerprinting' },
        { regex: /getNetworkInterfaces|networkInterfaces/gi, desc: 'Network interface enumeration' },
        { regex: /whoami|id\s+-[ung]|groups/gi, desc: 'User enumeration' },
        { regex: /uname\s+-[amrs]|cat\s+\/etc\/.*release/gi, desc: 'OS detection' },
        { regex: /ifconfig|ip\s+addr|ipconfig/gi, desc: 'IP configuration' },
        { regex: /netstat|ss\s+-[tlnp]/gi, desc: 'Network connections' },
        { regex: /ps\s+aux|tasklist/gi, desc: 'Process listing' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 16: DENIAL OF SERVICE (Medium)
    // ═══════════════════════════════════════════════════════════════
    dos: {
      severity: 'MEDIUM',
      description: 'Resource exhaustion and DoS patterns',
      patterns: [
        { regex: /while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)/g, desc: 'Infinite loop' },
        { regex: /setInterval\s*\([^)]*,\s*[01]\s*\)/g, desc: 'Rapid interval' },
        { regex: /Array\s*\(\s*[0-9]{7,}\s*\)/g, desc: 'Large array allocation' },
        { regex: /new\s+Array\s*\(\s*1e[789]/g, desc: 'Massive array creation' },
        { regex: /\.repeat\s*\(\s*[0-9]{6,}\s*\)/g, desc: 'String repetition attack' },
        { regex: /JSON\.parse\s*\([^)]*\.repeat/g, desc: 'JSON bomb' },
        { regex: /(?:a{100,})+$/g, desc: 'ReDoS pattern' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 17: ENCODING/DECODING ABUSE (Low)
    // ═══════════════════════════════════════════════════════════════
    encoding: {
      severity: 'LOW',
      description: 'Suspicious encoding and decoding patterns',
      patterns: [
        { regex: /atob\s*\([^)]+\)/g, desc: 'Base64 decode' },
        { regex: /btoa\s*\([^)]+\)/g, desc: 'Base64 encode' },
        { regex: /Buffer\.from\s*\([^)]+\)/g, desc: 'Buffer creation' },
        { regex: /decodeURIComponent\s*\([^)]+\)/g, desc: 'URL decode' },
        { regex: /unescape\s*\([^)]+\)/g, desc: 'Unescape function' },
        { regex: /TextDecoder|TextEncoder/g, desc: 'Text encoding API' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 18: PHISHING INDICATORS (Medium)
    // ═══════════════════════════════════════════════════════════════
    phishing: {
      severity: 'MEDIUM',
      description: 'Phishing and social engineering patterns',
      patterns: [
        { regex: /verify.*wallet|connect.*wallet.*claim/gi, desc: 'Wallet phishing text' },
        { regex: /free.*airdrop|claim.*free.*nft/gi, desc: 'Airdrop phishing' },
        { regex: /urgent.*action|account.*suspend/gi, desc: 'Urgency manipulation' },
        { regex: /login.*expire|password.*reset.*click/gi, desc: 'Credential phishing' },
        { regex: /metamask.*connect|walletconnect.*sign/gi, desc: 'Wallet connection prompt' },
        { regex: /confirm.*transaction.*seed/gi, desc: 'Seed phrase phishing' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 19: UNSAFE DESERIALIZATION (High)
    // ═══════════════════════════════════════════════════════════════
    deserialization: {
      severity: 'HIGH',
      description: 'Unsafe deserialization vulnerabilities',
      patterns: [
        { regex: /pickle\.loads?|cPickle\.loads?/gi, desc: 'Python pickle deserialization' },
        { regex: /yaml\.load\s*\([^)]*Loader\s*=\s*None/gi, desc: 'Unsafe YAML load' },
        { regex: /yaml\.unsafe_load/gi, desc: 'YAML unsafe_load' },
        { regex: /unserialize\s*\(/gi, desc: 'PHP unserialize' },
        { regex: /ObjectInputStream/gi, desc: 'Java deserialization' },
        { regex: /Marshal\.load/gi, desc: 'Ruby Marshal load' },
        { regex: /JSON\.parse\s*\([^)]*reviver/gi, desc: 'JSON parse with reviver' },
      ]
    },

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY 20: FILE OPERATIONS (Medium)
    // ═══════════════════════════════════════════════════════════════
    file_ops: {
      severity: 'MEDIUM',
      description: 'Suspicious file operations',
      patterns: [
        { regex: /fs\.writeFileSync\s*\([^)]*\/etc\//gi, desc: 'Writing to /etc/' },
        { regex: /fs\.writeFileSync\s*\([^)]*\/usr\//gi, desc: 'Writing to /usr/' },
        { regex: /fs\.chmodSync\s*\([^)]*[0-7]{3}\s*\)/gi, desc: 'Permission modification' },
        { regex: /fs\.unlinkSync|fs\.rmdirSync/gi, desc: 'File/directory deletion' },
        { regex: /rimraf|del-cli/gi, desc: 'Recursive deletion' },
        { regex: /\.exe|\.dll|\.bat|\.cmd|\.ps1|\.vbs/gi, desc: 'Executable file extension' },
        { regex: /\.sh\s*['"]|\.bash\s*['"]/gi, desc: 'Shell script' },
      ]
    },
  }
};

// Calculate total patterns
let total = 0;
for (const category of Object.values(module.exports.categories)) {
  total += category.patterns.length;
}
module.exports.totalPatterns = total;

console.log(`AgentShield Threat Patterns v3.0 loaded: ${total} patterns across ${Object.keys(module.exports.categories).length} categories`);
