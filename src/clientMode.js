const fs = require('fs');
const path = require('path');
const { execFile, exec } = require('child_process');
const { promisify } = require('util');

const axios = require('axios');

const execFileAsync = promisify(execFile);
const execAsync = promisify(exec);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function readNumber(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) {
      return fallback;
    }
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    const value = Number(raw);
    return Number.isFinite(value) ? value : fallback;
  } catch {
    return fallback;
  }
}

function writeNumber(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, String(value));
}

function readText(filePath, fallback = '') {
  try {
    if (!fs.existsSync(filePath)) {
      return fallback;
    }
    return fs.readFileSync(filePath, 'utf8').trim();
  } catch {
    return fallback;
  }
}

function writeText(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value);
}

function parseJwtExpMs(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return Date.now() + (10 * 60 * 1000);
    }
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!payload.exp) {
      return Date.now() + (10 * 60 * 1000);
    }
    return Number(payload.exp) * 1000;
  } catch {
    return Date.now() + (10 * 60 * 1000);
  }
}

function parseNftSetOutput(raw) {
  const data = JSON.parse(raw);
  for (const entry of data.nftables || []) {
    if (!entry.set) {
      continue;
    }
    const elems = entry.set.elem || [];
    const ips = [];
    for (const item of elems) {
      if (typeof item === 'string') {
        ips.push(item);
        continue;
      }
      if (item && typeof item === 'object') {
        const inner = item.elem || item;
        if (typeof inner === 'string') {
          ips.push(inner);
          continue;
        }
        if (inner && typeof inner === 'object' && typeof inner.val === 'string') {
          ips.push(inner.val);
        }
      }
    }
    return ips.filter(Boolean);
  }
  return [];
}

async function getBannedIps(nftFamily, nftTable, nftSet) {
  try {
    const { stdout } = await execFileAsync('nft', ['-j', 'list', 'set', nftFamily, nftTable, nftSet], { timeout: 10000 });
    return parseNftSetOutput(stdout);
  } catch (err) {
    if (err.code === 'ENOENT') {
      console.error('[ERROR] nft command not found on this host');
    } else {
      const msg = err.stderr ? String(err.stderr).trim() : err.message;
      console.error(`[ERROR] Failed to read nft set: ${msg}`);
    }
    return [];
  }
}

function buildEvent(node, type, ip, reason, ports) {
  return {
    ts: Math.floor(Date.now() / 1000),
    node,
    type,
    ip,
    reason,
    ports,
  };
}

function parseKvFromMessage(message) {
  const out = {};
  const regex = /\b([A-Z]{2,20})=([^\s]*)/g;
  let match = regex.exec(message);
  while (match) {
    out[match[1]] = match[2];
    match = regex.exec(message);
  }
  return out;
}

function toInt(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return undefined;
  }
  return Math.floor(num);
}

function parseSmtpGuardEventFromJournal(entry, node) {
  const message = entry && typeof entry.MESSAGE === 'string' ? entry.MESSAGE : '';
  if (!message.includes('SMTP-GUARD ')) {
    return null;
  }

  let action = 'other';
  if (message.includes('SMTP-GUARD BAN')) {
    action = 'ban';
  } else if (message.includes('SMTP-GUARD OK')) {
    action = 'ok';
  }

  const kv = parseKvFromMessage(message);
  const spt = toInt(kv.SPT);
  const dpt = toInt(kv.DPT);
  const tsMicros = Number(entry.__REALTIME_TIMESTAMP);
  const ts = Number.isFinite(tsMicros) ? Math.floor(tsMicros / 1000000) : Math.floor(Date.now() / 1000);

  return {
    ts,
    node,
    type: 'packet',
    action,
    src: kv.SRC,
    dst: kv.DST,
    spt,
    dpt,
    proto: kv.PROTO,
    inIf: kv.IN,
    outIf: kv.OUT,
    ip: kv.SRC,
    reason: action === 'ban' ? 'smtp_guard_ban' : 'smtp_guard_ok',
    ports: Number.isFinite(dpt) ? [dpt] : undefined,
    message,
    payload: {
      mac: kv.MAC,
      len: kv.LEN,
      ttl: kv.TTL,
      tos: kv.TOS,
      id: kv.ID,
      window: kv.WINDOW,
      res: kv.RES,
      urgp: kv.URGP,
    },
  };
}

async function collectJournalPacketEvents(options) {
  const {
    journalctlBin,
    journalGrep,
    journalCursorFile,
    journalBatchLimit,
    journalTimeoutMs,
    node,
  } = options;

  const cursor = readText(journalCursorFile, '');
  const args = ['-k', '--no-pager', '-o', 'json', '--grep', journalGrep, '-n', String(journalBatchLimit)];
  if (cursor) {
    args.push('--after-cursor', cursor);
  }

  let stdout = '';
  try {
    const result = await execFileAsync(journalctlBin, args, {
      timeout: journalTimeoutMs,
      maxBuffer: 20 * 1024 * 1024,
    });
    stdout = result.stdout || '';
  } catch (err) {
    const msg = err.stderr ? String(err.stderr).trim() : err.message;
    throw new Error(`journalctl read failed: ${msg}`);
  }

  if (!stdout.trim()) {
    return [];
  }

  const lines = stdout.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const events = [];
  let lastCursor = cursor;

  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (entry && typeof entry.__CURSOR === 'string') {
        lastCursor = entry.__CURSOR;
      }

      const evt = parseSmtpGuardEventFromJournal(entry, node);
      if (evt) {
        events.push(evt);
      }
    } catch {
      // ignore malformed journal lines
    }
  }

  if (lastCursor && lastCursor !== cursor) {
    writeText(journalCursorFile, lastCursor);
  }

  return events;
}

function loadJsonlLinesFromOffset(filePath, offset) {
  if (!fs.existsSync(filePath)) {
    return { nextOffset: offset, events: [] };
  }

  const stat = fs.statSync(filePath);
  let safeOffset = offset;
  if (safeOffset > stat.size) {
    safeOffset = 0;
  }

  const full = fs.readFileSync(filePath, 'utf8');
  const chunk = full.slice(safeOffset);
  const nextOffset = Buffer.byteLength(full, 'utf8');

  const lines = chunk.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const events = [];
  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        events.push(obj);
      }
    } catch {
      console.warn('[WARN] Skipping invalid JSONL line');
    }
  }

  return { nextOffset, events };
}

async function collectNftConfig(nftFamily, nftTable, nftSet, nftRulesetCmd) {
  let bannedSet = null;
  let ruleset = null;

  try {
    const { stdout } = await execFileAsync('nft', ['-j', 'list', 'set', nftFamily, nftTable, nftSet], { timeout: 10000 });
    bannedSet = JSON.parse(stdout);
  } catch (err) {
    bannedSet = { error: 'failed_to_collect_set', detail: err.message };
  }

  try {
    const { stdout } = await execAsync(nftRulesetCmd, { timeout: 10000 });
    ruleset = stdout;
  } catch (err) {
    ruleset = `error: ${err.message}`;
  }

  return {
    collectedAt: new Date().toISOString(),
    bannedSet,
    ruleset,
  };
}

async function startClient() {
  const serverUrl = (process.env.SERVER_URL || '').replace(/\/$/, '');
  const node = process.env.NODE_NAME || '';
  const username = process.env.CLIENT_USERNAME || '';
  const password = process.env.CLIENT_PASSWORD || '';

  const intervalMs = Number(process.env.INTERVAL_MS || 10000);
  const logsPushMs = Number(process.env.LOG_PUSH_INTERVAL_MS || 10000);
  const reversePollMs = Number(process.env.REVERSE_POLL_INTERVAL_MS || 10000);
  const jwtRefreshSkewMs = Number(process.env.JWT_REFRESH_SKEW_MS || 60000);

  const nftFamily = process.env.NFT_FAMILY || 'inet';
  const nftTable = process.env.NFT_TABLE || 'pve_smtp_guard';
  const nftSet = process.env.NFT_SET || 'banned_v4';
  const nftRulesetCmd = process.env.NFT_RULESET_CMD || 'nft list ruleset';

  const packetSource = (process.env.PACKET_SOURCE || 'journal').trim().toLowerCase();
  const packetLogFile = process.env.PACKET_LOG_FILE || path.join(process.cwd(), 'data', 'packet-events.jsonl');
  const packetLogOffsetFile = process.env.PACKET_LOG_OFFSET_FILE || path.join(process.cwd(), 'data', '.packet-log.offset');
  const packetLogTruncateAfterSend = parseBoolean(process.env.PACKET_LOG_TRUNCATE_AFTER_SEND, true);

  const journalctlBin = process.env.JOURNALCTL_BIN || 'journalctl';
  const journalGrep = process.env.JOURNAL_GREP || 'SMTP-GUARD';
  const journalCursorFile = process.env.JOURNAL_CURSOR_FILE || path.join(process.cwd(), 'data', '.smtp-guard.cursor');
  const journalBatchLimit = Number(process.env.JOURNAL_BATCH_LIMIT || 500);
  const journalTimeoutMs = Number(process.env.JOURNAL_TIMEOUT_MS || 10000);

  if (!serverUrl || !node || !username || !password) {
    console.error('[FATAL] Missing SERVER_URL, NODE_NAME, CLIENT_USERNAME or CLIENT_PASSWORD for client mode');
    process.exit(1);
  }

  const loginUrl = `${serverUrl}/api/login`;
  const changeUrl = `${serverUrl}/api/change`;
  const logsUrl = `${serverUrl}/api/logs`;
  const reversePollUrl = `${serverUrl}/api/reverse/poll`;
  const reverseSubmitUrl = `${serverUrl}/api/reverse/submit`;

  console.log(`[INFO] Client mode started for node=${node}, user=${username}, packet_source=${packetSource}`);

  let previous = new Set();
  let firstRun = true;
  let packetOffset = readNumber(packetLogOffsetFile, 0);
  let authToken = '';
  let authTokenExpMs = 0;
  let loginInFlight = null;

  async function loginNow() {
    const resp = await axios.post(loginUrl, { username, password }, { timeout: 10000 });
    const token = resp.data && resp.data.token;
    if (!token || typeof token !== 'string') {
      throw new Error('Missing token in /api/login response');
    }

    authToken = token;
    authTokenExpMs = parseJwtExpMs(token);
    console.log('[AUTH] Login success');
  }

  async function ensureLoggedIn() {
    const now = Date.now();
    if (authToken && now < (authTokenExpMs - jwtRefreshSkewMs)) {
      return;
    }

    if (loginInFlight) {
      await loginInFlight;
      return;
    }

    loginInFlight = loginNow()
      .catch((err) => {
        const status = err.response ? err.response.status : 'no_status';
        throw new Error(`Login failed (${status})`);
      })
      .finally(() => {
        loginInFlight = null;
      });

    await loginInFlight;
  }

  function authHeaders() {
    return {
      Authorization: `Bearer ${authToken}`,
    };
  }

  async function postJson(url, payload) {
    await ensureLoggedIn();
    return axios.post(url, payload, {
      timeout: 10000,
      headers: authHeaders(),
    });
  }

  async function getJson(url, params) {
    await ensureLoggedIn();
    return axios.get(url, {
      params,
      timeout: 10000,
      headers: authHeaders(),
    });
  }

  await ensureLoggedIn();

  async function monitorBanListLoop() {
    while (true) {
      const currentList = await getBannedIps(nftFamily, nftTable, nftSet);
      const current = new Set(currentList);

      if (firstRun) {
        previous = current;
        firstRun = false;
        console.log(`[INFO] Initial snapshot: ${current.size} IPs`);
      } else {
        const added = [...current].filter((ip) => !previous.has(ip)).sort();
        const removed = [...previous].filter((ip) => !current.has(ip)).sort();

        if (added.length || removed.length) {
          console.log(`[CHANGE] +${added.length} added, -${removed.length} removed`);

          try {
            await postJson(changeUrl, { node, added, removed });
          } catch (err) {
            const status = err.response ? err.response.status : 'no_status';
            console.error(`[ERROR] Failed notifying /api/change (${status})`);
          }

          const events = [];
          for (const ip of added) {
            events.push(buildEvent(node, 'ban', ip, 'smtp_rate_limit', [25, 465, 587]));
          }
          for (const ip of removed) {
            events.push(buildEvent(node, 'unban', ip, 'removed_from_set', [25, 465, 587]));
          }

          if (events.length) {
            try {
              await postJson(logsUrl, { node, events });
            } catch (err) {
              const status = err.response ? err.response.status : 'no_status';
              console.error(`[ERROR] Failed sending ban events to /api/logs (${status})`);
            }
          }
        } else {
          console.log(`[OK] No change (${current.size} IPs)`);
        }

        previous = current;
      }

      await sleep(intervalMs);
    }
  }

  async function pushPacketLogsLoop() {
    while (true) {
      try {
        let events = [];

        if (packetSource === 'journal') {
          events = await collectJournalPacketEvents({
            journalctlBin,
            journalGrep,
            journalCursorFile,
            journalBatchLimit,
            journalTimeoutMs,
            node,
          });
        } else {
          const result = loadJsonlLinesFromOffset(packetLogFile, packetOffset);
          packetOffset = result.nextOffset;
          writeNumber(packetLogOffsetFile, packetOffset);
          events = result.events.map((evt) => ({
            ...evt,
            node: typeof evt.node === 'string' && evt.node ? evt.node : node,
            ts: Number.isFinite(evt.ts) ? Number(evt.ts) : Math.floor(Date.now() / 1000),
          }));
        }

        if (events.length) {
          await postJson(logsUrl, { node, events });
          console.log(`[LOGS] sent ${events.length} packet events`);

          if (packetSource !== 'journal' && packetLogTruncateAfterSend) {
            try {
              fs.truncateSync(packetLogFile, 0);
              packetOffset = 0;
              writeNumber(packetLogOffsetFile, 0);
            } catch (err) {
              console.error(`[WARN] Could not truncate packet log file: ${err.message}`);
            }
          }
        }
      } catch (err) {
        const status = err.response ? err.response.status : 'no_status';
        console.error(`[ERROR] Packet log push failed (${status})`);
      }

      await sleep(logsPushMs);
    }
  }

  async function reversePollLoop() {
    while (true) {
      try {
        const resp = await getJson(reversePollUrl);
        const data = resp.data || {};

        if (data.pending && data.request && data.request.requestId) {
          const config = await collectNftConfig(nftFamily, nftTable, nftSet, nftRulesetCmd);

          await postJson(reverseSubmitUrl, {
            node,
            requestId: data.request.requestId,
            config,
          });

          console.log(`[REVERSE] submitted config for request=${data.request.requestId}`);
        }
      } catch (err) {
        const status = err.response ? err.response.status : 'no_status';
        console.error(`[ERROR] Reverse poll failed (${status})`);
      }

      await sleep(reversePollMs);
    }
  }

  await Promise.all([
    monitorBanListLoop(),
    pushPacketLogsLoop(),
    reversePollLoop(),
  ]);
}

module.exports = { startClient };
