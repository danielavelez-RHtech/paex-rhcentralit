/* ============================================================
 * Central IT · Gestão de Pessoas · API do Painel de Metas
 * Cloudflare Pages Function (roda junto com o site, mesmo endereço)
 *
 * Precisa de 3 configurações no projeto do Cloudflare Pages:
 *   KV binding  PAINEL_KV     → namespace KV onde ficam as marcações
 *   Secret      USERS_JSON    → {"dani":"senha","kennedy":"senha",...}
 *   Secret      TOKEN_SECRET  → texto aleatório longo (assina as sessões)
 *
 * Rotas:
 *   POST /api/login   {user, pass}            → {token, user}
 *   GET  /api/state                            → {done}
 *   POST /api/toggle  {id, done, resp}         → {done}
 *   GET  /api/log     (somente Dani e Kennedy) → últimas 500 marcações
 * ============================================================ */

const ADMINS = ['dani', 'kennedy'];
const NAMES = {
  dani:'Dani', kennedy:'Kennedy', gabrielly:'Gabrielly', larysa:'Larysa',
  mayara:'Mayara', bruna:'Bruna', dionisia:'Dionísia', renard:'Renard',
  guilherme:'Guilherme', jaime:'Jaime', freitas:'Freitas', emauri:'Emauri',
  lucas:'Lucas', dasio:'Dasio', pablo:'Pablo', victor:'Victor'
};
const STATE_KEY = 'state_v1';
const SESSION_HOURS = 12;
const MAX_FAILS = 8;          // tentativas erradas antes do bloqueio
const LOCK_SECONDS = 900;     // 15 minutos de bloqueio

const enc = new TextEncoder();

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
  });
}
function b64url(bytes) {
  let s = ''; const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return atob(s);
}
function safeEqual(a, b) {
  a = String(a); b = String(b);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}
async function makeToken(env, user) {
  const payload = b64url(enc.encode(JSON.stringify({ u: user, exp: Math.floor(Date.now() / 1000) + SESSION_HOURS * 3600 })));
  return payload + '.' + await hmac(env.TOKEN_SECRET, payload);
}
async function userFromRequest(env, request) {
  const auth = request.headers.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  if (!safeEqual(await hmac(env.TOKEN_SECRET, payload), sig)) return null;
  try {
    const data = JSON.parse(b64urlDecode(payload));
    if (!data.exp || data.exp < Math.floor(Date.now() / 1000)) return null;
    return data.u;
  } catch (e) { return null; }
}
function norm(t) {
  return String(t || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim();
}
async function readState(env) {
  const raw = await env.PAINEL_KV.get(STATE_KEY);
  const st = raw ? JSON.parse(raw) : {};
  st.done = st.done || {};
  st.log = st.log || [];
  return st;
}

export async function onRequest(context) {
  const { request, env, params } = context;
  const route = Array.isArray(params.route) ? params.route.join('/') : (params.route || '');
  const method = request.method;

  if (!env.PAINEL_KV || !env.USERS_JSON || !env.TOKEN_SECRET) {
    return json({ error: 'Servidor sem configuração (KV ou secrets ausentes).' }, 500);
  }

  // ── LOGIN ─────────────────────────────────────────────
  if (route === 'login' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const user = norm(body.user);
    const pass = String(body.pass || '');
    const failKey = 'fail:' + user;
    const fails = parseInt(await env.PAINEL_KV.get(failKey) || '0', 10);
    if (fails >= MAX_FAILS) {
      return json({ error: 'Muitas tentativas. Aguarde 15 minutos e tente de novo.' }, 429);
    }
    let users = {};
    try { users = JSON.parse(env.USERS_JSON); } catch (e) { return json({ error: 'USERS_JSON inválido.' }, 500); }
    if (users[user] !== undefined && safeEqual(users[user], pass)) {
      if (fails) await env.PAINEL_KV.delete(failKey);
      return json({ token: await makeToken(env, user), user });
    }
    await env.PAINEL_KV.put(failKey, String(fails + 1), { expirationTtl: LOCK_SECONDS });
    return json({ error: 'Usuário ou senha inválidos.' }, 401);
  }

  // ── Demais rotas exigem sessão ─────────────────────────
  const user = await userFromRequest(env, request);
  if (!user) return json({ error: 'Sessão inválida ou expirada.' }, 401);
  const isAdmin = ADMINS.includes(user);

  if (route === 'state' && method === 'GET') {
    const st = await readState(env);
    return json({ done: st.done, user });
  }

  if (route === 'toggle' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const id = String(body.id || '').slice(0, 200);
    if (!id) return json({ error: 'Ação não informada.' }, 400);
    if (!isAdmin) {
      const me = norm(NAMES[user] || user);
      const resps = String(body.resp || '').split('+').map(norm);
      if (!resps.includes(me)) return json({ error: 'Você não é responsável por esta ação.' }, 403);
    }
    const st = await readState(env);
    const at = new Date().toISOString();
    if (body.done) st.done[id] = { by: user, at };
    else delete st.done[id];
    st.log.push({ id, done: !!body.done, by: user, at });
    if (st.log.length > 500) st.log = st.log.slice(-500);
    await env.PAINEL_KV.put(STATE_KEY, JSON.stringify(st));
    return json({ done: st.done });
  }

  if (route === 'log' && method === 'GET') {
    if (!isAdmin) return json({ error: 'Acesso restrito.' }, 403);
    const st = await readState(env);
    return json({ log: st.log.slice().reverse() });
  }

  return json({ error: 'Rota não encontrada.' }, 404);
}
