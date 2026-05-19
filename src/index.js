require('dotenv').config();

const { startServer } = require('./serverMode');
const { startClient } = require('./clientMode');

const mode = (process.env.MODE || 'server').trim().toLowerCase();

async function main() {
  if (mode === 'server') {
    await startServer();
    return;
  }

  if (mode === 'client') {
    await startClient();
    return;
  }

  console.error(`[FATAL] Unsupported MODE='${mode}'. Use MODE=server or MODE=client.`);
  process.exit(1);
}

main().catch((err) => {
  console.error('[FATAL] Unhandled error:', err);
  process.exit(1);
});
