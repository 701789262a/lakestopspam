# lakestopspam

Repo unica che funziona sia da:
- `server` centralizzato (riceve ban change, log JSONL, reverse hook, login multi-account)
- `client` nodo remoto (legge nft, manda change + log packets, risponde al reverse hook)

## 1) Installazione

```bash
npm install
cp .env.example .env
```

## 2) Account login (YAML)

File: `config/accounts.yml`

Genera hash password:

```bash
npm run hash-password -- "una-password-forte"
```

Inserisci l'hash in `passwordHash`.

Login API:

```bash
curl -X POST http://127.0.0.1:8000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"una-password-forte"}'
```

## 3) Avvio modalità server

`.env`:

```env
MODE=server
HOST=0.0.0.0
PORT=8000
INGEST_API_KEY=super-secret-key
JWT_SECRET=cambia-subito
```

Run:

```bash
npm run start:server
```

Endpoint principali server:
- `GET /health`
- `POST /api/login`
- `POST /api/change` (node + apikey + added[] + removed[])
- `POST /api/logs` (JSON, array eventi o JSONL raw)
- `POST /api/reverse/request` (JWT required)
- `GET /api/reverse/poll?node=...&apikey=...`
- `POST /api/reverse/submit` (valida `ruleset`, poi applica automaticamente su server)
- `GET /api/reverse/latest/:node` (JWT required)
- `GET /api/status` (JWT required)
- `GET /api/status/:node` (JWT required)

## 4) Avvio modalità client

`.env`:

```env
MODE=client
SERVER_URL=http://IP_DEL_SERVER:8000
NODE_NAME=node-1
API_KEY=super-secret-key
NFT_FAMILY=inet
NFT_TABLE=pve_smtp_guard
NFT_SET=banned_v4
PACKET_LOG_FILE=./data/packet-events.jsonl
```

Run:

```bash
npm run start:client
```

Il client:
- monitora nft set `banned_v4`
- invia delta ban a `/api/change`
- invia eventi ban/unban e packet logs a `/api/logs`
- polla `/api/reverse/poll` e, se richiesto, invia conf nft a `/api/reverse/submit`
- usa solo `API_KEY` per autenticare le chiamate ingest (non usa JWT)

## 5) Payload supportati

### change

```json
{
  "node": "node-1",
  "apikey": "super-secret-key",
  "added": ["1.2.3.4"],
  "removed": ["5.6.7.8"]
}
```

### log event (JSONL/object)

```json
{
  "ts": 1710000000,
  "node": "node-1",
  "apikey": "super-secret-key",
  "type": "ban",
  "ip": "1.2.3.4",
  "reason": "smtp_rate_limit",
  "ports": [25, 465, 587]
}
```

### reverse request (admin)

```json
{
  "node": "node-1",
  "reason": "manual-check"
}
```

## Note

- Se imposti `NODE_API_KEYS`, il server valida chiavi per nodo (`node:key,node:key`) e ignora `INGEST_API_KEY`.
- Il JWT (`/api/login`) resta solo per endpoint amministrativi.
- I dati persistono su file JSON/JSONL in `./data`.
- Su `reverse/submit` il server prende `config.ruleset`, fa `nft -c -f` (validate), poi scrive `NFT_APPLY_PATH` (default `/etc/nftables.conf`) e fa `nft -f`.
- Se l'apply fallisce, tenta rollback dal backup `<NFT_APPLY_PATH>.bak-<timestamp>`.
