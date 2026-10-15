// Canal próprio da CN Serviços para chamadas mTLS à NFS-e Nacional.
// O servidor do Governo (IIS) pede o certificado por renegociação TLS 1.2,
// que o Deno das edge functions não suporta. Este serviço usa curl/OpenSSL,
// que comprovadamente completa essa conexão (teste de 15/10/2026).
//
// Segurança:
// - Exige Authorization: Bearer <NFSE_MTLS_RELAY_TOKEN> em toda chamada.
// - Só aceita destinos https em *.nfse.gov.br (não funciona como proxy aberto).
// - Certificado e chave chegam por chamada, são gravados com permissão 600
//   em pasta temporária e apagados ao final de cada requisição.
// - Nada é registrado em log além de status e erros de conexão.

import http from 'node:http';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const PORT = Number(process.env.PORT || 3000);
const TOKEN = process.env.NFSE_MTLS_RELAY_TOKEN || '';
const MAX_BODY = 12 * 1024 * 1024; // certificados e respostas são pequenos; margem generosa
const ALLOWED_HOST = /(^|\.)nfse\.gov\.br$/i;
const ALLOWED_METHODS = new Set(['GET', 'POST']);

function json(res, code, payload) {
  const data = JSON.stringify(payload);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) });
  res.end(data);
}

function authorized(req) {
  if (!TOKEN) return false;
  const a = Buffer.from(String(req.headers.authorization || ''));
  const b = Buffer.from(`Bearer ${TOKEN}`);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function runCurl(args) {
  return new Promise((resolve) => {
    const child = spawn('curl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => resolve({ code: -1, stdout, stderr: String(err) }));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') return json(res, 200, { ok: true });
  if (req.method !== 'POST' || req.url !== '/mtls-fetch') return json(res, 404, { error: 'not found' });
  if (!authorized(req)) return json(res, 401, { error: 'unauthorized' });

  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > MAX_BODY) return json(res, 413, { error: 'payload too large' });
  }

  let payload;
  try { payload = JSON.parse(raw); } catch { return json(res, 400, { error: 'invalid json' }); }

  const { url, method = 'GET', cert_pem, key_pem, headers = {}, body_base64 } = payload || {};
  if (typeof url !== 'string' || typeof cert_pem !== 'string' || typeof key_pem !== 'string') {
    return json(res, 400, { error: 'url, cert_pem e key_pem são obrigatórios' });
  }
  if (!ALLOWED_METHODS.has(method)) return json(res, 400, { error: 'método não permitido' });

  let target;
  try { target = new URL(url); } catch { return json(res, 400, { error: 'url inválida' }); }
  if (target.protocol !== 'https:' || !ALLOWED_HOST.test(target.hostname)) {
    return json(res, 403, { error: 'destino fora da lista permitida (apenas *.nfse.gov.br)' });
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mtls-'));
  try {
    const certPath = path.join(dir, 'cert.pem');
    const keyPath = path.join(dir, 'key.pem');
    const outPath = path.join(dir, 'response.bin');
    fs.writeFileSync(certPath, cert_pem, { mode: 0o600 });
    fs.writeFileSync(keyPath, key_pem, { mode: 0o600 });

    const args = ['-sS', '--http1.1', '--max-time', '25', '--cert', certPath, '--key', keyPath,
      '-X', method, '-o', outPath, '-w', '%{http_code}'];

    if (headers && typeof headers === 'object') {
      for (const [name, value] of Object.entries(headers)) {
        const n = String(name), v = String(value);
        if (/[\r\n]/.test(n) || /[\r\n]/.test(v)) continue;
        args.push('-H', `${n}: ${v}`);
      }
    }
    if (typeof body_base64 === 'string' && body_base64.length > 0) {
      const bodyPath = path.join(dir, 'request.bin');
      fs.writeFileSync(bodyPath, Buffer.from(body_base64, 'base64'), { mode: 0o600 });
      args.push('--data-binary', `@${bodyPath}`);
    }
    args.push(url);

    const result = await runCurl(args);
    const status = Number.parseInt(result.stdout.trim(), 10);
    if (result.code !== 0 || !Number.isFinite(status) || status <= 0) {
      console.error('[relay] falha de conexão curl code=%s err=%s', result.code, result.stderr.slice(0, 200));
      return json(res, 200, { success: false, status: 0, error: 'CONNECTION_FAILED', detail: result.stderr.slice(0, 300) });
    }
    const respBody = fs.existsSync(outPath) ? fs.readFileSync(outPath) : Buffer.alloc(0);
    return json(res, 200, { success: true, status, body_base64: respBody.toString('base64') });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

server.listen(PORT, () => console.log(`nfse-mtls-relay ouvindo na porta ${PORT}`));
