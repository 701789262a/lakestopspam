# lakestopspam

Repo unica che funziona sia da:
- `server` centralizzato
- `client` nodo remoto con nft

Modello auth:
- i client fanno `POST /api/login` con `username/password` (da `accounts.yml` sul server)
- il server restituisce JWT
- il client usa il JWT per tutte le chiamate (`/api/change`, `/api/logs`, `/api/reverse/poll`, `/api/reverse/submit`)
- non si usa API key

## 1) Installazione

```bash
npm install
cp .env.example .env
```

## 2) Config account YAML sul server

File: `config/accounts.yml`

Esempio:
- account `admin` per API amministrative
- account `client` legato a uno specifico `node`

Genera hash password:

```bash
npm run hash-password -- "una-password-forte"
```

## 3) Avvio modalità server

`.env`:

```env
MODE=server
HOST=0.0.0.0
PORT=8000
JWT_SECRET=cambia-subito
ACCOUNTS_FILE=./config/accounts.yml
AUTO_APPLY_NFT_ON_SUBMIT=true
NFT_APPLY_PATH=/etc/nftables.conf
```

Run:

```bash
npm run start:server
```

Endpoint server:
- `GET /health`
- `POST /api/login`
- `POST /api/change` (JWT client)
- `POST /api/logs` (JWT client)
- `GET /api/reverse/poll` (JWT client)
- `POST /api/reverse/submit` (JWT client)
- `POST /api/reverse/request` (JWT admin)
- `GET /api/reverse/latest/:node` (JWT admin)
- `GET /api/status` (JWT admin)
- `GET /api/status/:node` (JWT admin)

## 4) Avvio modalità client

`.env`:

```env
MODE=client
SERVER_URL=http://IP_DEL_SERVER:8000
NODE_NAME=node-1
CLIENT_USERNAME=node-1
CLIENT_PASSWORD=node-password
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
- fa login automatico all'avvio
- rinnova il JWT prima della scadenza
- monitora nft set `banned_v4`
- invia delta ban a `/api/change`
- invia eventi ban/unban e packet logs a `/api/logs`
- polla `/api/reverse/poll` e, se richiesto, invia conf nft a `/api/reverse/submit`

## 5) Payload supportati

### change

```json
{
  "node": "node-1",
  "added": ["1.2.3.4"],
  "removed": ["5.6.7.8"]
}
```

### log event

```json
{
  "ts": 1710000000,
  "node": "node-1",
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

- Su `reverse/submit` il server prende `config.ruleset`, fa `nft -c -f`, poi scrive `NFT_APPLY_PATH` e fa `nft -f`.
- Se l'apply fallisce, tenta rollback da backup `<NFT_APPLY_PATH>.bak-<timestamp>`.
- Il processo server deve avere permessi per scrivere `NFT_APPLY_PATH` e lanciare `nft -f`.
