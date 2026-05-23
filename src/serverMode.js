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
    const tsMs = normalizeEpochMs(item.ts);
    const row = [
      item.ts,
      tsMs ? new Date(tsMs).toISOString() : '',
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

function normalizeEpochMs(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    return null;
  }
  if (Math.abs(num) >= 1e12) {
    return Math.floor(num);
  }
  return Math.floor(num * 1000);
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

function isValidIpv4(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const ip = value.trim();
  const match = ip.match(/^(\d{1,3})(\.\d{1,3}){3}$/);
  if (!match) {
    return false;
  }
  const parts = ip.split('.');
  return parts.every((part) => {
    const n = Number(part);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

function normalizeIpv4List(...parts) {
  const out = [];
  for (const part of parts) {
    if (typeof part === 'string') {
      const trimmed = part.trim();
      if (trimmed) {
        out.push(trimmed);
      }
      continue;
    }
    if (Array.isArray(part)) {
      for (const item of part) {
        if (typeof item === 'string' && item.trim()) {
          out.push(item.trim());
        }
      }
    }
  }

  const unique = Array.from(new Set(out));
  return unique.filter(isValidIpv4);
}

function normalizeEvent(input, fallbackNode) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return null;
  }

  const event = {
    ts: Number.isFinite(input.ts) ? (normalizeEpochMs(input.ts) || Date.now()) : Date.now(),
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

  if (event.type === 'packet') {
    const msg = typeof event.message === 'string' ? event.message.toUpperCase() : '';
    if ((!event.action || event.action === 'other') && msg) {
      if (msg.includes('SMTP-GUARD RETRY')) {
        event.action = 'retry';
      } else if (msg.includes('SMTP-GUARD BAN')) {
        event.action = 'ban';
      } else if (msg.includes('SMTP-GUARD OK')) {
        event.action = 'ok';
      }
    }
  }

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
    if (typeof config.nftablesConf === 'string' && config.nftablesConf.trim()) {
      return config.nftablesConf;
    }
    if (typeof config.ruleset === 'string' && config.ruleset.trim()) {
      return config.ruleset;
    }
  }

  return null;
}

async function validateNftRulesetOnly(ruleset, options) {
  const {
    nftBinary,
    timeoutMs,
  } = options;

  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tempFile = path.join(os.tmpdir(), `lakemailblock-nft-${stamp}.conf`);
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

  return {
    validated: true,
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
  const nodeActivityFile = process.env.NODE_ACTIVITY_FILE || path.join(process.cwd(), 'data', 'node_activity.json');
  const logsFile = process.env.LOGS_FILE || path.join(process.cwd(), 'data', 'events.jsonl');
  const logsCsvFile = process.env.LOGS_CSV_FILE || path.join(process.cwd(), 'data', 'events.csv');
  const nodeOnlineTtlMs = Math.max(1000, Number(process.env.NODE_ONLINE_TTL_MS || 300000));
  const validateRulesetOnServer = parseBoolean(process.env.VALIDATE_RULESET_ON_SERVER, true);
  const nftBinary = process.env.NFT_BIN || 'nft';
  const nftCmdTimeoutMs = Number(process.env.NFT_CMD_TIMEOUT_MS || 10000);
  const reverseRefreshWaitMs = parsePositiveInt(process.env.REVERSE_REFRESH_WAIT_MS, 20000);
  const reverseRefreshPollMs = Math.max(100, parsePositiveInt(process.env.REVERSE_REFRESH_POLL_MS, 500));

  const stateRaw = readJsonFile(stateFile, {});
  const state = new Map(Object.entries(stateRaw).map(([node, ips]) => [node, new Set(Array.isArray(ips) ? ips : [])]));

  const reverseRequests = readJsonFile(reverseFile, {});
  const nftStore = readJsonFile(nftStoreFile, {});
  const nodeActivity = readJsonFile(nodeActivityFile, {});

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

  function persistNodeActivity() {
    writeJsonFile(nodeActivityFile, nodeActivity);
  }

  function markNodeSeen(node, source, by) {
    if (typeof node !== 'string' || !node) {
      return;
    }
    const nowTs = Date.now();
    nodeActivity[node] = {
      lastSeenAt: new Date(nowTs).toISOString(),
      lastSeenTs: nowTs,
      source: typeof source === 'string' ? source : 'unknown',
      by: typeof by === 'string' ? by : undefined,
    };
    persistNodeActivity();
  }

  function getNodeOnlineInfo() {
    const nowTs = Date.now();
    const latestAccounts = loadAccounts(accountsPath);
    const knownNodes = new Set([
      ...Object.keys(nodeActivity),
      ...Object.keys(nftStore),
      ...Object.keys(reverseRequests),
      ...Array.from(state.keys()),
    ]);
    for (const user of latestAccounts.values()) {
      if (user && user.role === 'client' && typeof user.node === 'string' && user.node) {
        knownNodes.add(user.node);
      }
    }

    const onlineNodes = [];
    const offlineNodes = [];
    const details = {};

    for (const node of knownNodes) {
      const meta = nodeActivity[node] || null;
      const lastSeenTs = meta && Number.isFinite(meta.lastSeenTs) ? Number(meta.lastSeenTs) : null;
      const isOnline = lastSeenTs !== null && (nowTs - lastSeenTs) <= nodeOnlineTtlMs;
      const item = {
        node,
        online: isOnline,
        lastSeenAt: meta ? meta.lastSeenAt : null,
        lastSeenTs,
        source: meta ? (meta.source || null) : null,
      };
      details[node] = item;
      if (isOnline) {
        onlineNodes.push(node);
      } else {
        offlineNodes.push(node);
      }
    }

    onlineNodes.sort();
    offlineNodes.sort();
    return {
      nowTs,
      ttlMs: nodeOnlineTtlMs,
      onlineNodes,
      offlineNodes,
      details,
    };
  }

  function queueCollectConfigRequest(node, requestedBy, reason) {
    const existing = reverseRequests[node];
    if (existing && existing.status === 'pending') {
      if (existing.type !== 'collect_config') {
        return {
          queued: false,
          blocked: true,
          node,
          requestId: existing.requestId,
          type: existing.type || 'unknown',
          status: existing.status,
        };
      }
      return {
        queued: false,
        node,
        requestId: existing.requestId,
        type: existing.type || 'collect_config',
        status: existing.status,
      };
    }

    const requestId = makeRequestId();
    reverseRequests[node] = {
      requestId,
      type: 'collect_config',
      requestedAt: new Date().toISOString(),
      requestedBy,
      reason: typeof reason === 'string' ? reason : 'manual',
      status: 'pending',
    };
    persistReverse();
    return {
      queued: true,
      node,
      requestId,
      type: 'collect_config',
      status: 'pending',
    };
  }

  async function waitForCollectCompletion(node, requestId, timeoutMs, pollMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const current = reverseRequests[node];
      if (!current) {
        return { ok: false, reason: 'missing_request' };
      }
      if (current.requestId !== requestId) {
        return { ok: false, reason: 'request_replaced', current };
      }
      if (current.status === 'completed') {
        return { ok: true, current };
      }
      if (current.status === 'failed') {
        return { ok: false, reason: 'failed', current };
      }
      await sleep(pollMs);
    }

    return {
      ok: false,
      reason: 'timeout',
      current: reverseRequests[node],
    };
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

    if (role === 'client' && node) {
      markNodeSeen(node, 'login', username);
    }

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
    markNodeSeen(node, 'change', req.user && req.user.sub);

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
    markNodeSeen(node, 'logs', req.user && req.user.sub);

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

    const queued = queueCollectConfigRequest(node, req.user.sub, typeof reason === 'string' ? reason : 'manual');
    return res.json({ status: 'ok', ...queued });
  });

  app.post('/api/reverse/refresh', ...requireAdmin, (req, res) => {
    const { node, reason } = req.body || {};
    if (typeof node !== 'string' || !node) {
      return res.status(400).json({ detail: 'node is required' });
    }

    const queued = queueCollectConfigRequest(
      node,
      req.user.sub,
      typeof reason === 'string' ? reason : 'refresh_current_file'
    );
    return res.json({ status: 'ok', action: 'refresh_current_file', ...queued });
  });

  app.post('/api/config/push', ...requireAdmin, async (req, res) => {
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

    if (validateRulesetOnServer) {
      try {
        await validateNftRulesetOnly(normalizedRuleset, {
          nftBinary,
          timeoutMs: nftCmdTimeoutMs,
        });
      } catch (err) {
        return res.status(400).json({ detail: `ruleset validation failed: ${err.message}` });
      }
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

  app.post('/api/unban', ...requireAdmin, (req, res) => {
    const {
      node,
      ip,
      ips,
      reason,
    } = req.body || {};

    if (typeof node !== 'string' || !node.trim()) {
      return res.status(400).json({ detail: 'node is required' });
    }
    const normalizedNode = node.trim();

    const requestedIps = normalizeIpv4List(ip, ips);
    if (!requestedIps.length) {
      return res.status(400).json({ detail: 'ip or ips[] (valid IPv4) is required' });
    }

    const existing = reverseRequests[normalizedNode];
    if (existing && existing.status === 'pending') {
      return res.status(409).json({
        detail: `Node ${normalizedNode} already has a pending request (${existing.type || 'unknown'})`,
        requestId: existing.requestId,
      });
    }

    const requestId = makeRequestId();
    reverseRequests[normalizedNode] = {
      requestId,
      type: 'unban_ips',
      requestedAt: new Date().toISOString(),
      requestedBy: req.user.sub,
      reason: typeof reason === 'string' && reason.trim() ? reason.trim() : 'admin_manual_unban',
      status: 'pending',
      unban: {
        ips: requestedIps,
      },
    };
    persistReverse();

    return res.json({
      status: 'ok',
      node: normalizedNode,
      requestId,
      type: 'unban_ips',
      queuedIps: requestedIps,
      count: requestedIps.length,
    });
  });

  app.post('/api/protection', ...requireAdmin, (req, res) => {
    const {
      node,
      action,
      reason,
    } = req.body || {};

    if (typeof node !== 'string' || !node.trim()) {
      return res.status(400).json({ detail: 'node is required' });
    }
    const normalizedNode = node.trim();

    const normalizedAction = typeof action === 'string' ? action.trim().toLowerCase() : '';
    if (normalizedAction !== 'pause' && normalizedAction !== 'resume') {
      return res.status(400).json({ detail: "action must be 'pause' or 'resume'" });
    }

    const existing = reverseRequests[normalizedNode];
    if (existing && existing.status === 'pending') {
      return res.status(409).json({
        detail: `Node ${normalizedNode} already has a pending request (${existing.type || 'unknown'})`,
        requestId: existing.requestId,
      });
    }

    const requestId = makeRequestId();
    const requestType = normalizedAction === 'pause' ? 'pause_protection' : 'resume_protection';
    reverseRequests[normalizedNode] = {
      requestId,
      type: requestType,
      requestedAt: new Date().toISOString(),
      requestedBy: req.user.sub,
      reason: typeof reason === 'string' && reason.trim() ? reason.trim() : `admin_${normalizedAction}_protection`,
      status: 'pending',
      protection: {
        action: normalizedAction,
      },
    };
    persistReverse();

    return res.json({
      status: 'ok',
      node: normalizedNode,
      requestId,
      type: requestType,
      action: normalizedAction,
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
    markNodeSeen(node, 'reverse_poll', req.user && req.user.sub);

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
        unban: reqState.type === 'unban_ips' ? reqState.unban : undefined,
        protection: (reqState.type === 'pause_protection' || reqState.type === 'resume_protection')
          ? reqState.protection
          : undefined,
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
    markNodeSeen(node, 'reverse_submit', req.user && req.user.sub);

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

    let validation = {
      validatedOnServer: false,
    };

    if (validateRulesetOnServer) {
      try {
        validation = {
          validatedOnServer: true,
          ...(await validateNftRulesetOnly(ruleset, {
            nftBinary,
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
      validation,
    };
    persistNftStore();

    reqState.status = 'completed';
    reqState.completedAt = new Date().toISOString();
    persistReverse();

    console.log(`[REVERSE] node=${node} request=${requestId} submitted validated=${validation.validatedOnServer}`);
    return res.json({ status: 'ok', node, validation: nftStore[node].validation });
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
    markNodeSeen(node, 'config_ack', req.user && req.user.sub);

    const reqState = reverseRequests[node];
    if (!reqState || reqState.requestId !== requestId) {
      return res.status(404).json({ detail: 'No matching pending request' });
    }
    if (
      reqState.type !== 'push_config'
      && reqState.type !== 'unban_ips'
      && reqState.type !== 'pause_protection'
      && reqState.type !== 'resume_protection'
    ) {
      return res.status(409).json({ detail: 'Request type mismatch: expected push_config, unban_ips, pause_protection or resume_protection' });
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
      if (reqState.type === 'unban_ips') {
        const reqIps = normalizeIpv4List(reqState.unban && reqState.unban.ips);
        const current = state.get(node) || new Set();
        const removed = [];
        for (const candidate of reqIps) {
          if (current.delete(candidate)) {
            removed.push(candidate);
          }
        }
        state.set(node, current);
        persistState();

        if (removed.length) {
          const nowTs = Date.now();
          const unbanEvents = removed.map((removedIp) => ({
            ts: nowTs,
            node,
            type: 'unban',
            ip: removedIp,
            reason: 'admin_manual_unban_ack',
            ports: [25, 465, 587],
            payload: {
              requestId,
            },
          }));
          appendJsonl(logsFile, unbanEvents);
          appendEventsCsv(logsCsvFile, unbanEvents);
        }
      }

      if (reqState.type === 'pause_protection') {
        const current = state.get(node) || new Set();
        const removed = Array.from(current);
        state.set(node, new Set());
        persistState();

        const nowTs = Date.now();
        const pauseEvent = {
          ts: nowTs,
          node,
          type: 'protection',
          action: 'pause',
          reason: 'admin_pause_protection_ack',
          payload: {
            requestId,
            removedBans: removed.length,
          },
        };
        appendJsonl(logsFile, [pauseEvent]);
        appendEventsCsv(logsCsvFile, [pauseEvent]);
      }

      if (reqState.type === 'resume_protection') {
        const nowTs = Date.now();
        const resumeEvent = {
          ts: nowTs,
          node,
          type: 'protection',
          action: 'resume',
          reason: 'admin_resume_protection_ack',
          payload: {
            requestId,
          },
        };
        appendJsonl(logsFile, [resumeEvent]);
        appendEventsCsv(logsCsvFile, [resumeEvent]);
      }

      return res.status(200).json({ status: 'ok', node, requestId, type: reqState.type });
    }
    return res.status(400).json({
      status: 'error',
      node,
      requestId,
      detail: reqState.clientAck.error || 'Client reported action failure',
    });
  });

  app.get('/api/reverse/latest/:node', ...requireAdmin, async (req, res) => {
    const node = req.params.node;
    const refresh = queueCollectConfigRequest(node, req.user.sub, 'auto_refresh_latest_single');
    if (refresh.blocked) {
      return res.status(409).json({
        status: 'error',
        node,
        detail: `Pending non-collect request blocks refresh (${refresh.type}).`,
        refresh,
      });
    }

    const waited = await waitForCollectCompletion(
      node,
      refresh.requestId,
      reverseRefreshWaitMs,
      reverseRefreshPollMs
    );

    if (!waited.ok) {
      const data = nftStore[node];
      const httpStatus = waited.reason === 'failed' ? 400 : 504;
      return res.status(httpStatus).json({
        status: 'error',
        node,
        detail: waited.reason === 'failed' ? 'Client reported refresh failure' : 'Timed out waiting for client refresh',
        refresh,
        request: waited.current || null,
        data: data || null,
      });
    }

    const data = nftStore[node];
    if (!data) {
      return res.status(404).json({
        status: 'error',
        node,
        detail: 'Refresh completed but no snapshot stored for node',
        refresh,
      });
    }
    return res.json({ status: 'ok', node, data, refresh });
  });

  app.get('/api/reverse/latest', ...requireAdmin, async (req, res) => {
    const latestAccounts = loadAccounts(accountsPath);
    const knownNodes = new Set([
      ...Object.keys(nftStore),
      ...Object.keys(reverseRequests),
      ...Array.from(state.keys()),
    ]);

    for (const user of latestAccounts.values()) {
      if (user && user.role === 'client' && typeof user.node === 'string' && user.node) {
        knownNodes.add(user.node);
      }
    }

    const refresh = [];
    const waits = [];
    for (const node of knownNodes) {
      const q = queueCollectConfigRequest(node, req.user.sub, 'auto_refresh_latest_all');
      refresh.push(q);
      if (!q.blocked) {
        waits.push(waitForCollectCompletion(node, q.requestId, reverseRefreshWaitMs, reverseRefreshPollMs));
      }
    }

    if (waits.length) {
      await Promise.all(waits);
    }

    const output = {};
    for (const [node, data] of Object.entries(nftStore)) {
      output[node] = data;
    }
    return res.json({ status: 'ok', nodes: output, refresh });
  });

  app.get('/api/status', ...requireAdmin, (req, res) => {
    const output = {};
    for (const [node, ips] of state.entries()) {
      output[node] = Array.from(ips).sort();
    }
    return res.json(output);
  });

  app.get('/api/nodes/active', ...requireAdmin, (req, res) => {
    const info = getNodeOnlineInfo();
    return res.json({
      status: 'ok',
      nowTs: info.nowTs,
      ttlMs: info.ttlMs,
      onlineNodes: info.onlineNodes,
      offlineNodes: info.offlineNodes,
      details: info.details,
    });
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
    console.log(`[INFO] Server-side nft ruleset validation: ${validateRulesetOnServer ? 'enabled' : 'disabled'}`);
  });
}

module.exports = { startServer };
