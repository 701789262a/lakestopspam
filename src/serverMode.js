const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const axios = require('axios');
const bcrypt = require('bcryptjs');
const express = require('express');
const jwt = require('jsonwebtoken');
const yaml = require('js-yaml');

const execFileAsync = promisify(execFile);

function ensureDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function readJsonFile(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) {
      return fallback;
    }
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.warn(`[WARN] Failed reading JSON file ${filePath}:`, err.message);
    return fallback;
  }
}

function writeJsonFile(filePath, data) {
  ensureDir(filePath);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function appendJsonl(filePath, records) {
  ensureDir(filePath);
  const lines = records.map((item) => JSON.stringify(item)).join('\n') + '\n';
  fs.appendFileSync(filePath, lines);
}

function parseNodeApiKeys(raw) {
  const result = new Map();
  if (!raw) {
    return result;
  }

  for (const pair of raw.split(',')) {
    const trimmed = pair.trim();
    if (!trimmed) {
      continue;
    }
    const [node, key] = trimmed.split(':').map((x) => x && x.trim());
    if (node && key) {
      result.set(node, key);
    }
  }
  return result;
}

function parseBoolean(raw, fallback) {
  if (typeof raw !== 'string') {
    return fallback;
  }
  const value = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(value)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(value)) {
    return false;
  }
  return fallback;
}

function loadAccounts(accountsPath) {
  try {
    const raw = fs.readFileSync(accountsPath, 'utf8');
    const data = yaml.load(raw) || {};
    const users = Array.isArray(data.users) ? data.users : [];
    const byUsername = new Map();
    for (const entry of users) {
      if (!entry || typeof entry.username !== 'string') {
        continue;
      }
      byUsername.set(entry.username, entry);
    }
    return byUsername;
  } catch (err) {
    console.warn(`[WARN] Could not load accounts YAML at ${accountsPath}: ${err.message}`);
    return new Map();
  }
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function normalizeEvent(input, fallbackNode) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return null;
  }

  const event = {
    ts: Number.isFinite(input.ts) ? Number(input.ts) : Math.floor(Date.now() / 1000),
    node: typeof input.node === 'string' && input.node ? input.node : fallbackNode,
    type: typeof input.type === 'string' ? input.type : 'unknown',
    ip: typeof input.ip === 'string' ? input.ip : undefined,
    reason: typeof input.reason === 'string' ? input.reason : undefined,
    ports: Array.isArray(input.ports) ? input.ports.filter((p) => Number.isFinite(p)).map(Number) : undefined,
    payload: input.payload && typeof input.payload === 'object' ? input.payload : undefined,
  };

  if (!event.node) {
    return null;
  }

  return event;
}

function extractRulesetFromConfig(config) {
  if (typeof config === 'string' && config.trim()) {
    return config;
  }

  if (config && typeof config === 'object') {
    if (typeof config.ruleset === 'string' && config.ruleset.trim()) {
      return config.ruleset;
    }
    if (typeof config.nftablesConf === 'string' && config.nftablesConf.trim()) {
      return config.nftablesConf;
    }
  }

  return null;
}

async function validateAndApplyNftRuleset(ruleset, options) {
  const {
    nftBinary,
    nftApplyPath,
    timeoutMs,
  } = options;

  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tempFile = path.join(os.tmpdir(), `lakemailblock-nft-${stamp}.conf`);
  const backupFile = `${nftApplyPath}.bak-${stamp}`;

  ensureDir(nftApplyPath);
  fs.writeFileSync(tempFile, ruleset, { mode: 0o600 });

  try {
    await execFileAsync(nftBinary, ['-c', '-f', tempFile], { timeout: timeoutMs });
  } catch (err) {
    const stderr = err.stderr ? String(err.stderr).trim() : err.message;
    throw new Error(`nft validation failed: ${stderr}`);
  } finally {
    try {
      fs.unlinkSync(tempFile);
    } catch (err) {
      // ignore cleanup error
    }
  }

  const hadExistingTarget = fs.existsSync(nftApplyPath);
  if (hadExistingTarget) {
    fs.copyFileSync(nftApplyPath, backupFile);
  }

  fs.writeFileSync(nftApplyPath, ruleset);

  try {
    await execFileAsync(nftBinary, ['-f', nftApplyPath], { timeout: timeoutMs });
  } catch (err) {
    const stderr = err.stderr ? String(err.stderr).trim() : err.message;
    let rollback = 'not_attempted';

    if (hadExistingTarget && fs.existsSync(backupFile)) {
      try {
        fs.copyFileSync(backupFile, nftApplyPath);
        await execFileAsync(nftBinary, ['-f', nftApplyPath], { timeout: timeoutMs });
        rollback = 'restored_previous_config';
      } catch (rollbackErr) {
        rollback = `rollback_failed: ${rollbackErr.message}`;
      }
    }

    throw new Error(`nft apply failed: ${stderr}; rollback=${rollback}`);
  }

  return {
    nftApplyPath,
    backupFile: hadExistingTarget ? backupFile : null,
  };
}

function getBearerToken(req) {
  const auth = req.headers.authorization || '';
  const [kind, token] = auth.split(' ');
  if (kind !== 'Bearer' || !token) {
    return null;
  }
  return token;
}

function createAuthMiddleware(jwtSecret) {
  return (req, res, next) => {
    const token = getBearerToken(req);
    if (!token) {
      return res.status(401).json({ detail: 'Missing bearer token' });
    }

    try {
      const decoded = jwt.verify(token, jwtSecret);
      req.user = decoded;
      return next();
    } catch (err) {
      return res.status(401).json({ detail: 'Invalid token' });
    }
  };
}

async function sendTelegram(tgBotToken, tgChatId, text) {
  if (!tgBotToken || !tgChatId) {
    return;
  }

  const url = `https://api.telegram.org/bot${tgBotToken}/sendMessage`;
  try {
    await axios.post(url, {
      chat_id: tgChatId,
      text,
      parse_mode: 'HTML',
    }, { timeout: 10000 });
  } catch (err) {
    const status = err.response ? err.response.status : 'no_status';
    console.error(`[ERROR] Telegram send failed (${status})`);
  }
}

function buildBanMessage(node, added, removed, currentSet) {
  const lines = [`<b>Mailban - ${node}</b>`];

  if (added.length) {
    lines.push(`\n+ Aggiunti (${added.length})`);
    for (const ip of added) {
      lines.push(`<code>${ip}</code>`);
    }
  }

  if (removed.length) {
    lines.push(`\n- Rimossi (${removed.length})`);
    for (const ip of removed) {
      lines.push(`<code>${ip}</code>`);
    }
  }

  lines.push(`\nTotale bannati: ${currentSet.size}`);
  return lines.join('\n');
}

async function startServer() {
  const host = process.env.HOST || '0.0.0.0';
  const port = Number(process.env.PORT || 8000);

  const ingestApiKey = process.env.INGEST_API_KEY || process.env.API_KEY || '';
  const nodeApiKeys = parseNodeApiKeys(process.env.NODE_API_KEYS || '');

  const jwtSecret = process.env.JWT_SECRET || 'change-me-now';
  const jwtExpiry = process.env.JWT_EXPIRES_IN || '12h';
  const accountsPath = process.env.ACCOUNTS_FILE || path.join(process.cwd(), 'config', 'accounts.yml');

  const stateFile = process.env.STATE_FILE || path.join(process.cwd(), 'data', 'state.json');
  const reverseFile = process.env.REVERSE_FILE || path.join(process.cwd(), 'data', 'reverse_requests.json');
  const nftStoreFile = process.env.NFT_STORE_FILE || path.join(process.cwd(), 'data', 'nft_configs.json');
  const logsFile = process.env.LOGS_FILE || path.join(process.cwd(), 'data', 'events.jsonl');
  const autoApplyNftOnSubmit = parseBoolean(process.env.AUTO_APPLY_NFT_ON_SUBMIT, true);
  const nftApplyPath = process.env.NFT_APPLY_PATH || '/etc/nftables.conf';
  const nftBinary = process.env.NFT_BIN || 'nft';
  const nftCmdTimeoutMs = Number(process.env.NFT_CMD_TIMEOUT_MS || 10000);

  const tgBotToken = process.env.TG_BOT_TOKEN || '';
  const tgChatId = process.env.TG_CHAT_ID || '';

  const stateRaw = readJsonFile(stateFile, {});
  const state = new Map(Object.entries(stateRaw).map(([node, ips]) => [node, new Set(Array.isArray(ips) ? ips : [])]));

  const reverseRequests = readJsonFile(reverseFile, {});
  const nftStore = readJsonFile(nftStoreFile, {});

  let accounts = loadAccounts(accountsPath);

  const app = express();
  app.use(express.json({ limit: '2mb' }));
  app.use(express.text({ type: ['application/x-ndjson', 'text/plain'], limit: '5mb' }));

  const requireLogin = createAuthMiddleware(jwtSecret);

  function checkIngestAuth(node, apikey) {
    if (!apikey || typeof apikey !== 'string') {
      return false;
    }

    if (nodeApiKeys.size > 0) {
      const expected = nodeApiKeys.get(node);
      return expected ? apikey === expected : false;
    }

    return ingestApiKey ? apikey === ingestApiKey : false;
  }

  function persistState() {
    const serializable = {};
    for (const [node, set] of state.entries()) {
      serializable[node] = Array.from(set).sort();
    }
    writeJsonFile(stateFile, serializable);
  }

  function persistReverse() {
    writeJsonFile(reverseFile, reverseRequests);
  }

  function persistNftStore() {
    writeJsonFile(nftStoreFile, nftStore);
  }

  app.get('/health', (req, res) => {
    res.json({ status: 'ok', mode: 'server' });
  });

  app.post('/api/login', async (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ detail: 'username and password are required' });
    }

    accounts = loadAccounts(accountsPath);
    const user = accounts.get(username);
    if (!user) {
      return res.status(401).json({ detail: 'Invalid credentials' });
    }

    let valid = false;
    if (typeof user.passwordHash === 'string' && user.passwordHash) {
      valid = await bcrypt.compare(password, user.passwordHash);
    } else if (typeof user.password === 'string') {
      valid = password === user.password;
    }

    if (!valid) {
      return res.status(401).json({ detail: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { sub: username, role: user.role || 'user' },
      jwtSecret,
      { expiresIn: jwtExpiry }
    );

    return res.json({ status: 'ok', token, user: { username, role: user.role || 'user' } });
  });

  app.post('/api/change', async (req, res) => {
    const { node, apikey, added, removed } = req.body || {};

    if (typeof node !== 'string' || !isStringArray(added) || !isStringArray(removed)) {
      return res.status(400).json({ detail: 'Invalid payload format' });
    }

    if (!checkIngestAuth(node, apikey)) {
      return res.status(401).json({ detail: 'Invalid API key' });
    }

    const current = state.get(node) || new Set();
    for (const ip of added) {
      current.add(ip);
    }
    for (const ip of removed) {
      current.delete(ip);
    }
    state.set(node, current);
    persistState();

    console.log(`[CHANGE] node=${node} +${added.length} -${removed.length} total=${current.size}`);

    if (added.length || removed.length) {
      const message = buildBanMessage(node, added, removed, current);
      await sendTelegram(tgBotToken, tgChatId, message);
    }

    return res.json({ status: 'ok', node, total: current.size });
  });

  app.post('/api/logs', (req, res) => {
    const body = req.body;
    let apikey = null;
    let node = null;
    let events = [];

    if (typeof body === 'string') {
      const lines = body.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          if (parsed && typeof parsed === 'object') {
            events.push(parsed);
          }
        } catch (err) {
          return res.status(400).json({ detail: 'Invalid JSONL line' });
        }
      }
      if (events.length > 0) {
        node = events[0].node;
        apikey = events[0].apikey;
      }
    } else if (Array.isArray(body)) {
      events = body;
      node = events[0] && events[0].node;
      apikey = events[0] && events[0].apikey;
    } else if (body && typeof body === 'object') {
      if (Array.isArray(body.events)) {
        events = body.events;
      } else {
        events = [body];
      }
      node = body.node || (events[0] && events[0].node);
      apikey = body.apikey || (events[0] && events[0].apikey);
    }

    if (!node || !checkIngestAuth(node, apikey)) {
      return res.status(401).json({ detail: 'Invalid API key' });
    }

    const normalized = [];
    for (const event of events) {
      const clean = normalizeEvent(event, node);
      if (!clean) {
        return res.status(400).json({ detail: 'Invalid event format' });
      }
      normalized.push(clean);
    }

    appendJsonl(logsFile, normalized);
    return res.json({ status: 'ok', received: normalized.length });
  });

  app.post('/api/reverse/request', requireLogin, (req, res) => {
    const { node, reason } = req.body || {};
    if (typeof node !== 'string' || !node) {
      return res.status(400).json({ detail: 'node is required' });
    }

    const requestId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    reverseRequests[node] = {
      requestId,
      requestedAt: new Date().toISOString(),
      requestedBy: req.user.sub,
      reason: typeof reason === 'string' ? reason : 'manual',
      status: 'pending',
    };
    persistReverse();

    return res.json({ status: 'ok', node, requestId });
  });

  app.get('/api/reverse/poll', (req, res) => {
    const node = typeof req.query.node === 'string' ? req.query.node : '';
    const apikey = typeof req.query.apikey === 'string' ? req.query.apikey : '';

    if (!node || !checkIngestAuth(node, apikey)) {
      return res.status(401).json({ detail: 'Invalid API key' });
    }

    const reqState = reverseRequests[node];
    if (!reqState || reqState.status !== 'pending') {
      return res.json({ status: 'ok', pending: false });
    }

    return res.json({
      status: 'ok',
      pending: true,
      request: {
        requestId: reqState.requestId,
        reason: reqState.reason,
        requestedAt: reqState.requestedAt,
      },
    });
  });

  app.post('/api/reverse/submit', async (req, res) => {
    const { node, apikey, requestId, config } = req.body || {};

    if (typeof node !== 'string' || !node) {
      return res.status(400).json({ detail: 'node is required' });
    }

    if (!checkIngestAuth(node, apikey)) {
      return res.status(401).json({ detail: 'Invalid API key' });
    }

    const reqState = reverseRequests[node];
    if (!reqState || reqState.requestId !== requestId) {
      return res.status(404).json({ detail: 'No matching pending request' });
    }

    const ruleset = extractRulesetFromConfig(config);
    if (!ruleset) {
      return res.status(400).json({ detail: 'Missing nft ruleset in config.ruleset' });
    }

    let applyResult = {
      autoApplied: false,
      nftApplyPath,
      backupFile: null,
    };

    if (autoApplyNftOnSubmit) {
      try {
        applyResult = {
          autoApplied: true,
          ...(await validateAndApplyNftRuleset(ruleset, {
            nftBinary,
            nftApplyPath,
            timeoutMs: nftCmdTimeoutMs,
          })),
        };
      } catch (err) {
        reqState.status = 'failed';
        reqState.failedAt = new Date().toISOString();
        reqState.error = err.message;
        persistReverse();
        return res.status(400).json({ detail: err.message });
      }
    }

    nftStore[node] = {
      updatedAt: new Date().toISOString(),
      requestId,
      config,
      apply: {
        autoApplied: applyResult.autoApplied,
        nftApplyPath: applyResult.nftApplyPath,
        backupFile: applyResult.backupFile,
      },
    };
    persistNftStore();

    reqState.status = 'completed';
    reqState.completedAt = new Date().toISOString();
    persistReverse();

    console.log(`[REVERSE] node=${node} request=${requestId} submitted auto_applied=${applyResult.autoApplied}`);
    return res.json({
      status: 'ok',
      apply: nftStore[node].apply,
    });
  });

  app.get('/api/reverse/latest/:node', requireLogin, (req, res) => {
    const node = req.params.node;
    const data = nftStore[node];
    if (!data) {
      return res.status(404).json({ detail: 'Node not found' });
    }
    return res.json({ status: 'ok', node, data });
  });

  app.get('/api/status', requireLogin, (req, res) => {
    const output = {};
    for (const [node, ips] of state.entries()) {
      output[node] = Array.from(ips).sort();
    }
    return res.json(output);
  });

  app.get('/api/status/:node', requireLogin, (req, res) => {
    const node = req.params.node;
    if (!state.has(node)) {
      return res.status(404).json({ detail: 'Node not found' });
    }
    const banned = Array.from(state.get(node)).sort();
    return res.json({ node, banned, total: banned.length });
  });

  app.listen(port, host, () => {
    console.log(`[INFO] Server listening on ${host}:${port}`);
    console.log(`[INFO] Accounts YAML: ${accountsPath}`);
    if (!ingestApiKey && nodeApiKeys.size === 0) {
      console.warn('[WARN] No ingest API key configured (INGEST_API_KEY / NODE_API_KEYS). Ingest endpoints will reject requests.');
    }
    if (jwtSecret === 'change-me-now') {
      console.warn('[WARN] JWT_SECRET is default value. Change it in production.');
    }
    console.log(`[INFO] Reverse submit auto-apply nft: ${autoApplyNftOnSubmit ? 'enabled' : 'disabled'}`);
    if (autoApplyNftOnSubmit) {
      console.log(`[INFO] nft apply target: ${nftApplyPath}`);
    }
  });
}

module.exports = { startServer };
