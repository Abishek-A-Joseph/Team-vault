const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = __dirname;
const PORT = Number(process.env.PORT || 4173);
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']]
]);
const workspaces = new Map();
const clients = new Set();

function send(res, status, data, type = 'application/json') {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(type.includes('json') ? JSON.stringify(data) : data);
}
function body(req) {
  return new Promise((resolve, reject) => {
    let value = '';
    req.on('data', chunk => { value += chunk; if (value.length > 20_000_000) reject(new Error('Payload too large')); });
    req.on('end', () => { try { resolve(JSON.parse(value || '{}')); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}
function broadcast(payload) {
  const text = JSON.stringify(payload);
  const data = Buffer.from(text);
  let header;
  if (data.length < 126) header = Buffer.from([0x81, data.length]);
  else if (data.length < 65536) { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 126; header.writeUInt16BE(data.length, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x81; header[1] = 127; header.writeBigUInt64BE(BigInt(data.length), 2); }
  const frame = Buffer.concat([header, data]);
  for (const client of clients) { if (client.writable) client.write(frame); else clients.delete(client); }
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname === '/api/health') return send(res, 200, { ok: true, storage: 'memory', encryption: 'client-side' });
    if (url.pathname === '/api/workspaces' && req.method === 'GET') {
      const list = [...workspaces].map(([id, records]) => ({ id, count: records.length }));
      return send(res, 200, list);
    }
    if (url.pathname.startsWith('/api/workspaces/')) {
      const id = decodeURIComponent(url.pathname.slice('/api/workspaces/'.length));
      if (req.method === 'GET') return send(res, 200, workspaces.get(id) || []);
      if (req.method === 'POST') {
        const item = await body(req);
        if (!item.ciphertext || !item.iv || !item.id) return send(res, 400, { error: 'Encrypted payload required' });
        const rows = workspaces.get(id) || [];
        rows.push({ id: String(item.id), iv: String(item.iv), ciphertext: String(item.ciphertext), version: Number(item.version || 1), createdAt: Date.now() });
        workspaces.set(id, rows);
        broadcast({ type: 'activity', event: { id: crypto.randomUUID(), workspaceId: id, kind: 'file', actor: String(item.actor || 'A teammate'), at: Date.now() } });
        return send(res, 201, { ok: true, stored: 'ciphertext only', version: rows.at(-1).version });
      }
      if (req.method === 'DELETE') {
        const rows = workspaces.get(id) || [];
        workspaces.set(id, rows.filter(item => item.id !== url.searchParams.get('file')));
        return send(res, 200, { ok: true });
      }
    }
    const asset = assets.get(url.pathname);
    if (asset) return send(res, 200, fs.readFileSync(path.join(root, asset[0])), asset[1]);
    send(res, 404, { error: 'Not found' });
  } catch (error) { send(res, 400, { error: error.message }); }
});
server.on('upgrade', (req, socket) => {
  if (req.url !== '/live' || !req.headers['sec-websocket-key']) return socket.destroy();
  const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  clients.add(socket);
  socket.on('close', () => clients.delete(socket));
  socket.on('error', () => clients.delete(socket));
});
server.listen(PORT, '0.0.0.0', () => console.log(`TeamVault is running at http://localhost:${PORT}`));
