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

async function postJson(url, payload) {
  return axios.post(url, payload, { timeout: 10000 });
}

async function getJson(url, params) {
  return axios.get(url, { params, timeout: 10000 });
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

function buildChangePayload(node, apikey, added, removed) {
  return { node, apikey, added, removed };
}

function buildEvent(node, type, ip, reason, ports) {
  return {
    ts: Math.floor(Date.now() / 1000),
    node,
    apikey: process.env.API_KEY,
    type,
    ip,
    reason,
    ports,
  };
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
    } catch (err) {
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
  const apikey = process.env.API_KEY || '';

  const intervalMs = Number(process.env.INTERVAL_MS || 10000);
  const logsPushMs = Number(process.env.LOG_PUSH_INTERVAL_MS || 10000);
  const reversePollMs = Number(process.env.REVERSE_POLL_INTERVAL_MS || 10000);

  const nftFamily = process.env.NFT_FAMILY || 'inet';
  const nftTable = process.env.NFT_TABLE || 'pve_smtp_guard';
  const nftSet = process.env.NFT_SET || 'banned_v4';
  const nftRulesetCmd = process.env.NFT_RULESET_CMD || 'nft list ruleset';

  const packetLogFile = process.env.PACKET_LOG_FILE || path.join(process.cwd(), 'data', 'packet-events.jsonl');
  const packetLogOffsetFile = process.env.PACKET_LOG_OFFSET_FILE || path.join(process.cwd(), 'data', '.packet-log.offset');

  if (!serverUrl || !node || !apikey) {
    console.error('[FATAL] Missing SERVER_URL, NODE_NAME or API_KEY for client mode');
    process.exit(1);
  }

  const changeUrl = `${serverUrl}/api/change`;
  const logsUrl = `${serverUrl}/api/logs`;
  const reversePollUrl = `${serverUrl}/api/reverse/poll`;
  const reverseSubmitUrl = `${serverUrl}/api/reverse/submit`;

  console.log(`[INFO] Client mode started for node=${node}`);

  let previous = new Set();
  let firstRun = true;
  let packetOffset = readNumber(packetLogOffsetFile, 0);

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
            await postJson(changeUrl, buildChangePayload(node, apikey, added, removed));
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
              await postJson(logsUrl, { node, apikey, events });
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
        const { nextOffset, events } = loadJsonlLinesFromOffset(packetLogFile, packetOffset);
        packetOffset = nextOffset;
        writeNumber(packetLogOffsetFile, packetOffset);

        if (events.length) {
          const normalized = events.map((evt) => ({
            ...evt,
            node: typeof evt.node === 'string' && evt.node ? evt.node : node,
            apikey,
            ts: Number.isFinite(evt.ts) ? Number(evt.ts) : Math.floor(Date.now() / 1000),
          }));

          await postJson(logsUrl, { node, apikey, events: normalized });
          console.log(`[LOGS] sent ${normalized.length} packet events`);
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
        const resp = await getJson(reversePollUrl, { node, apikey });
        const data = resp.data || {};

        if (data.pending && data.request && data.request.requestId) {
          const config = await collectNftConfig(nftFamily, nftTable, nftSet, nftRulesetCmd);

          await postJson(reverseSubmitUrl, {
            node,
            apikey,
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
