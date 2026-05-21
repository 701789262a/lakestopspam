const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

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

function csvEscape(value) {
  if (value === undefined || value === null) {
    return '';
  }
  const raw = String(value);
  if (/[",\n]/.test(raw)) {
    return `"${raw.replace(/"/g, '""')}"`;
  }
  return raw;
}

function appendEventsCsv(filePath, records) {
  if (!records.length) {
    return;
  }
  ensureDir(filePath);

  const header = [
    'ts',
    'ts_iso',
    'node',
    'type',
    'action',
    'src',
    'dst',
    'spt',
    'dpt',
    'proto',
    'in_if',
    'out_if',
    'ip',
    'reason',
    'ports',
    'message',
    'payload',
  ].join(',');

  if (!fs.existsSync(filePath) || fs.statSync(filePath).size === 0) {
    fs.writeFileSync(filePath, `${header}\n`);
  }

  const lines = records.map((item) => {
    const row = [
      item.ts,
      item.ts ? new Date(item.ts * 1000).toISOString() : '',
      item.node,
      item.type,
      item.action,
      item.src,
      item.dst,
      item.spt,
      item.dpt,
      item.proto,
      item.inIf,
      item.outIf,
      item.ip,
      item.reason,
      item.ports ? JSON.stringify(item.ports) : '',
      item.message,
      item.payload ? JSON.stringify(item.payload) : '',
    ].map(csvEscape);
    return row.join(',');
  }).join('\n');

  fs.appendFileSync(filePath, `${lines}\n`);
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
    action: typeof input.action === 'string' ? input.action : undefined,
    src: typeof input.src === 'string' ? input.src : undefined,
    dst: typeof input.dst === 'string' ? input.dst : undefined,
    spt: Number.isFinite(input.spt) ? Number(input.spt) : undefined,
    dpt: Number.isFinite(input.dpt) ? Number(input.dpt) : undefined,
    proto: typeof input.proto === 'string' ? input.proto : undefined,
    inIf: typeof input.inIf === 'string' ? input.inIf : undefined,
    outIf: typeof input.outIf === 'string' ? input.outIf : undefined,
    message: typeof input.message === 'string' ? input.message : undefined,
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

function parsePositiveInt(value, fallback) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return Math.floor(parsed);
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
    } catch {
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
    } catch {
      return res.status(401).json({ detail: 'Invalid token' });
    }
  };
}

function requireRole(allowedRoles) {
  return (req, res, next) => {
    const role = req.user && req.user.role;
    if (!role || !allowedRoles.includes(role)) {
      return res.status(403).json({ detail: 'Insufficient role' });
    }
    return next();
  };
}

function resolveNodeFromRequest(req, providedNode) {
  const role = req.user && req.user.role;
  const tokenNode = req.user && req.user.node;

  if (role === 'admin') {
    const node = typeof providedNode === 'string' && providedNode ? providedNode : tokenNode;
    return node || null;
  }

  if (!tokenNode) {
    return null;
  }

  if (typeof providedNode === 'string' && providedNode && providedNode !== tokenNode) {
    return '__forbidden__';
  }

  return tokenNode;
}

function buildBanMessage(node, added, removed, currentSet) {
  const lines = [
    `node=${node}`,
    `added=${added.length}`,
    `removed=${removed.length}`,
    `total=${currentSet.size}`,
  ];
  return lines.join(' ');
}

function makeRequestId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

async function startServer() {
  const host = process.env.HOST || '0.0.0.0';
  const port = Number(process.env.PORT || 8000);

  const jwtSecret = process.env.JWT_SECRET || 'change-me-now';
  const jwtExpiry = process.env.JWT_EXPIRES_IN || '12h';
  const accountsPath = process.env.ACCOUNTS_FILE || path.join(process.cwd(), 'config', 'accounts.yml');

  const stateFile = process.env.STATE_FILE || path.join(process.cwd(), 'data', 'state.json');
  const reverseFile = process.env.REVERSE_FILE || path.join(process.cwd(), 'data', 'reverse_requests.json');
  const nftStoreFile = process.env.NFT_STORE_FILE || path.join(process.cwd(), 'data', 'nft_configs.json');
  const logsFile = process.env.LOGS_FILE || path.join(process.cwd(), 'data', 'events.jsonl');
  const logsCsvFile = process.env.LOGS_CSV_FILE || path.join(process.cwd(), 'data', 'events.csv');
  const autoApplyNftOnSubmit = parseBoolean(process.env.AUTO_APPLY_NFT_ON_SUBMIT, true);
  const nftApplyPath = process.env.NFT_APPLY_PATH || '/etc/nftables.conf';
  const nftBinary = process.env.NFT_BIN || 'nft';
  const nftCmdTimeoutMs = Number(process.env.NFT_CMD_TIMEOUT_MS || 10000);

  const stateRaw = readJsonFile(stateFile, {});
  const state = new Map(Object.entries(stateRaw).map(([node, ips]) => [node, new Set(Array.isArray(ips) ? ips : [])]));

  const reverseRequests = readJsonFile(reverseFile, {});
  const nftStore = readJsonFile(nftStoreFile, {});

  let accounts = loadAccounts(accountsPath);

  const app = express();
  app.use(express.json({ limit: '2mb' }));
  app.use(express.text({ type: ['application/x-ndjson', 'text/plain'], limit: '5mb' }));

  const requireAuth = createAuthMiddleware(jwtSecret);
  const requireAdmin = [requireAuth, requireRole(['admin'])];

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

    const role = typeof user.role === 'string' && user.role ? user.role : 'client';
    const node = typeof user.node === 'string' ? user.node : undefined;

    const token = jwt.sign(
      { sub: username, role, node },
      jwtSecret,
      { expiresIn: jwtExpiry }
    );

    return res.json({
      status: 'ok',
      token,
      user: { username, role, node: node || null },
    });
  });

  app.post('/api/change', requireAuth, (req, res) => {
    const { node: bodyNode, added, removed } = req.body || {};

    if (!isStringArray(added) || !isStringArray(removed)) {
      return res.status(400).json({ detail: 'Invalid payload format' });
    }

    const node = resolveNodeFromRequest(req, bodyNode);
    if (!node) {
      return res.status(403).json({ detail: 'Node missing in token' });
    }
    if (node === '__forbidden__') {
      return res.status(403).json({ detail: 'Node mismatch with token' });
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

    console.log(`[CHANGE] ${buildBanMessage(node, added, removed, current)}`);

    return res.json({ status: 'ok', node, total: current.size });
  });

  app.post('/api/logs', requireAuth, (req, res) => {
    const body = req.body;
    let bodyNode = null;
    let events = [];

    if (typeof body === 'string') {
      const lines = body.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          if (parsed && typeof parsed === 'object') {
            events.push(parsed);
          }
        } catch {
          return res.status(400).json({ detail: 'Invalid JSONL line' });
        }
      }
      if (events.length > 0) {
        bodyNode = events[0].node;
      }
    } else if (Array.isArray(body)) {
      events = body;
      bodyNode = events[0] && events[0].node;
    } else if (body && typeof body === 'object') {
      if (Array.isArray(body.events)) {
        events = body.events;
      } else {
        events = [body];
      }
      bodyNode = body.node || (events[0] && events[0].node);
    }

    const node = resolveNodeFromRequest(req, bodyNode);
    if (!node) {
      return res.status(403).json({ detail: 'Node missing in token' });
    }
    if (node === '__forbidden__') {
      return res.status(403).json({ detail: 'Node mismatch with token' });
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
    appendEventsCsv(logsCsvFile, normalized);
    return res.json({ status: 'ok', node, received: normalized.length });
  });

  app.get('/api/logs', ...requireAdmin, (req, res) => {
    const nodeFilter = typeof req.query.node === 'string' ? req.query.node : '';
    const typeFilter = typeof req.query.type === 'string' ? req.query.type : '';
    const fromTs = parsePositiveInt(req.query.fromTs, 0);
    const toTs = parsePositiveInt(req.query.toTs, Number.MAX_SAFE_INTEGER);
    const limitRaw = parsePositiveInt(req.query.limit, 200);
    const limit = Math.min(Math.max(limitRaw, 1), 5000);

    if (!fs.existsSync(logsFile)) {
      return res.json({
        status: 'ok',
        total: 0,
        logs: [],
      });
    }

    const lines = fs.readFileSync(logsFile, 'utf8')
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean);

    const results = [];
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      try {
        const obj = JSON.parse(lines[i]);
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
          continue;
        }

        if (nodeFilter && obj.node !== nodeFilter) {
          continue;
        }
        if (typeFilter && obj.type !== typeFilter) {
          continue;
        }

        const ts = Number.isFinite(obj.ts) ? Number(obj.ts) : 0;
        if (ts < fromTs || ts > toTs) {
          continue;
        }

        results.push(obj);
        if (results.length >= limit) {
          break;
        }
      } catch {
        // skip malformed lines
      }
    }

    results.reverse();
    return res.json({
      status: 'ok',
      total: results.length,
      logs: results,
    });
  });

  app.get('/api/packets', ...requireAdmin, (req, res) => {
    const nodeFilter = typeof req.query.node === 'string' ? req.query.node : '';
    const actionFilter = typeof req.query.action === 'string' ? req.query.action : '';
    const fromTs = parsePositiveInt(req.query.fromTs, 0);
    const toTs = parsePositiveInt(req.query.toTs, Number.MAX_SAFE_INTEGER);
    const limitRaw = parsePositiveInt(req.query.limit, 200);
    const limit = Math.min(Math.max(limitRaw, 1), 5000);

    if (!fs.existsSync(logsFile)) {
      return res.json({ status: 'ok', total: 0, packets: [] });
    }

    const lines = fs.readFileSync(logsFile, 'utf8')
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean);

    const packets = [];
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      try {
        const obj = JSON.parse(lines[i]);
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
          continue;
        }
        if (obj.type !== 'packet') {
          continue;
        }
        if (nodeFilter && obj.node !== nodeFilter) {
          continue;
        }
        if (actionFilter && obj.action !== actionFilter) {
          continue;
        }

        const ts = Number.isFinite(obj.ts) ? Number(obj.ts) : 0;
        if (ts < fromTs || ts > toTs) {
          continue;
        }

        packets.push(obj);
        if (packets.length >= limit) {
          break;
        }
      } catch {
        // skip malformed lines
      }
    }

    packets.reverse();
    return res.json({
      status: 'ok',
      total: packets.length,
      packets,
    });
  });

  app.post('/api/reverse/request', ...requireAdmin, (req, res) => {
    const { node, reason } = req.body || {};
    if (typeof node !== 'string' || !node) {
      return res.status(400).json({ detail: 'node is required' });
    }

    const requestId = makeRequestId();
    reverseRequests[node] = {
      requestId,
      type: 'collect_config',
      requestedAt: new Date().toISOString(),
      requestedBy: req.user.sub,
      reason: typeof reason === 'string' ? reason : 'manual',
      status: 'pending',
    };
    persistReverse();

    return res.json({ status: 'ok', node, requestId });
  });

  app.post('/api/config/push', ...requireAdmin, (req, res) => {
    const {
      node,
      nodes,
      ruleset,
      reason,
    } = req.body || {};

    const normalizedRuleset = typeof ruleset === 'string' ? ruleset.trim() : '';
    if (!normalizedRuleset) {
      return res.status(400).json({ detail: 'ruleset is required' });
    }

    let targetNodes = [];
    if (typeof node === 'string' && node.trim()) {
      targetNodes = [node.trim()];
    } else if (Array.isArray(nodes)) {
      targetNodes = nodes
        .filter((x) => typeof x === 'string')
        .map((x) => x.trim())
        .filter(Boolean);
    }

    if (!targetNodes.length) {
      return res.status(400).json({ detail: 'node or nodes[] is required' });
    }

    targetNodes = Array.from(new Set(targetNodes));
    const queued = [];
    for (const targetNode of targetNodes) {
      const requestId = makeRequestId();
      reverseRequests[targetNode] = {
        requestId,
        type: 'push_config',
        requestedAt: new Date().toISOString(),
        requestedBy: req.user.sub,
        reason: typeof reason === 'string' ? reason : 'push_config',
        status: 'pending',
        config: {
          ruleset: normalizedRuleset,
        },
      };
      queued.push({
        node: targetNode,
        requestId,
      });
    }
    persistReverse();

    return res.json({
      status: 'ok',
      queued,
      count: queued.length,
    });
  });

  app.get('/api/reverse/poll', requireAuth, (req, res) => {
    const node = resolveNodeFromRequest(req, req.query.node);
    if (!node) {
      return res.status(403).json({ detail: 'Node missing in token' });
    }
    if (node === '__forbidden__') {
      return res.status(403).json({ detail: 'Node mismatch with token' });
    }

    const reqState = reverseRequests[node];
    if (!reqState || reqState.status !== 'pending') {
      return res.json({ status: 'ok', node, pending: false });
    }

    return res.json({
      status: 'ok',
      node,
      pending: true,
      request: {
        requestId: reqState.requestId,
        type: reqState.type || 'collect_config',
        reason: reqState.reason,
        requestedAt: reqState.requestedAt,
        config: reqState.type === 'push_config' ? reqState.config : undefined,
      },
    });
  });

  app.post('/api/reverse/submit', requireAuth, async (req, res) => {
    const { node: bodyNode, requestId, config } = req.body || {};

    const node = resolveNodeFromRequest(req, bodyNode);
    if (!node) {
      return res.status(403).json({ detail: 'Node missing in token' });
    }
    if (node === '__forbidden__') {
      return res.status(403).json({ detail: 'Node mismatch with token' });
    }

    const reqState = reverseRequests[node];
    if (!reqState || reqState.requestId !== requestId) {
      return res.status(404).json({ detail: 'No matching pending request' });
    }
    if (reqState.type && reqState.type !== 'collect_config') {
      return res.status(409).json({ detail: 'Request type mismatch: expected collect_config' });
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
    return res.json({ status: 'ok', node, apply: nftStore[node].apply });
  });

  app.post('/api/config/ack', requireAuth, (req, res) => {
    const {
      node: bodyNode,
      requestId,
      ok,
      error,
      details,
    } = req.body || {};

    const node = resolveNodeFromRequest(req, bodyNode);
    if (!node) {
      return res.status(403).json({ detail: 'Node missing in token' });
    }
    if (node === '__forbidden__') {
      return res.status(403).json({ detail: 'Node mismatch with token' });
    }

    const reqState = reverseRequests[node];
    if (!reqState || reqState.requestId !== requestId) {
      return res.status(404).json({ detail: 'No matching pending request' });
    }
    if (reqState.type !== 'push_config') {
      return res.status(409).json({ detail: 'Request type mismatch: expected push_config' });
    }

    const success = Boolean(ok);
    reqState.status = success ? 'completed' : 'failed';
    reqState.completedAt = new Date().toISOString();
    reqState.clientAck = {
      ok: success,
      error: typeof error === 'string' ? error : undefined,
      details: details && typeof details === 'object' ? details : undefined,
    };
    persistReverse();

    if (success) {
      return res.status(200).json({ status: 'ok', node, requestId });
    }
    return res.status(400).json({
      status: 'error',
      node,
      requestId,
      detail: reqState.clientAck.error || 'Client reported config apply failure',
    });
  });

  app.get('/api/reverse/latest/:node', ...requireAdmin, (req, res) => {
    const node = req.params.node;
    const data = nftStore[node];
    if (!data) {
      return res.status(404).json({ detail: 'Node not found' });
    }
    return res.json({ status: 'ok', node, data });
  });

  app.get('/api/status', ...requireAdmin, (req, res) => {
    const output = {};
    for (const [node, ips] of state.entries()) {
      output[node] = Array.from(ips).sort();
    }
    return res.json(output);
  });

  app.get('/api/status/:node', ...requireAdmin, (req, res) => {
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
