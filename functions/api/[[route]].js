// 도란도란 동물의숲 server (Cloudflare Pages Functions): own sign-in (login id + password), profile, check-record sync.
// Needs one D1 database bound to this Pages project as DB. Tables are made on the first request.
// No e-mail and no outside sign-in: a forgotten password is reset by the admin (the first account made).

const DAY = 86400000;
const SESSION_DAYS = 90;
const FRUITS = ["사과", "배", "복숭아", "체리", "오렌지"];
const PBKDF2_ITER = 100000;          // the most Workers allows
const MAX_FAILS = 5, LOCK_MS = 10 * 60000;
const MAX_CODE = 1500000;            // a backup code, well under D1's 2 MB row limit

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE, pw TEXT NOT NULL,
     name TEXT NOT NULL DEFAULT '', island TEXT NOT NULL DEFAULT '', fruit TEXT NOT NULL DEFAULT '',
     role TEXT NOT NULL DEFAULT '', must_change INTEGER NOT NULL DEFAULT 0,
     fails INTEGER NOT NULL DEFAULT 0, lock_until INTEGER NOT NULL DEFAULT 0, banned INTEGER NOT NULL DEFAULT 0,
     created INTEGER NOT NULL, seen INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)`,
  `CREATE TABLE IF NOT EXISTS sync (user_id TEXT PRIMARY KEY, rev INTEGER NOT NULL, code TEXT NOT NULL, updated INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS hits (k TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL)`,
];
let schemaReady = null;
function setup(db){
  if(!schemaReady) schemaReady = db.batch(SCHEMA.map(q => db.prepare(q))).catch(e => { schemaReady = null; throw e; });
  return schemaReady;
}

/* ---------- small helpers ---------- */
const enc = new TextEncoder();
function json(obj, status = 200, headers = {}){
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers } });
}
const fail = (error, status = 400, extra = {}) => json({ error, ...extra }, status);
function b64u(bytes){ let s = ""; for(const b of new Uint8Array(bytes)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function ub64u(s){ s = s.replace(/-/g, "+").replace(/_/g, "/"); const bin = atob(s + "===".slice((s.length + 3) % 4)); return Uint8Array.from(bin, c => c.charCodeAt(0)); }
const rand = n => b64u(crypto.getRandomValues(new Uint8Array(n)));
async function sha256(s){ return b64u(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
function sameBytes(a, b){
  if(a.length !== b.length) return false;
  if(crypto.subtle.timingSafeEqual) return crypto.subtle.timingSafeEqual(a, b);
  let d = 0; for(let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0;
}
async function pbkdf2(pw, salt, iter){
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256));
}
async function hashPw(pw){ const salt = crypto.getRandomValues(new Uint8Array(16)); return `p2$${PBKDF2_ITER}$${b64u(salt)}$${b64u(await pbkdf2(pw, salt, PBKDF2_ITER))}`; }
async function checkPw(pw, stored){
  const [kind, iter, salt, hash] = String(stored).split("$");
  if(kind !== "p2") return false;
  return sameBytes(await pbkdf2(pw, ub64u(salt), +iter), ub64u(hash));
}
// Login ids: 2-16 of 한글, a-z, 0-9, _ (stored lower-case). Names: game limits, 1-10 characters.
const cleanText = s => String(s ?? "").normalize("NFC").replace(/[\u0000-\u001f\u007f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g, "").replace(/\s+/g, " ").trim();
const chars = s => [...s].length;
const okLogin = s => /^[a-z0-9_가-힣]{2,16}$/.test(s);
const okPw = s => typeof s === "string" && chars(s) >= 8 && chars(s) <= 64;
const okName = s => chars(s) >= 1 && chars(s) <= 10;

function cookieName(url){ return url.protocol === "https:" ? "__Host-dn" : "dn"; }
function readCookie(req, name){
  for(const part of (req.headers.get("Cookie") || "").split(/;\s*/)){ const i = part.indexOf("="); if(i > 0 && part.slice(0, i) === name) return part.slice(i + 1); }
  return null;
}
function sessionCookie(url, value, maxAge){
  return `${cookieName(url)}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${url.protocol === "https:" ? "; Secure" : ""}`;
}
// Writes only from this site's own pages.
function sameSite(req, url){
  const o = req.headers.get("Origin");
  return o ? o === url.origin : req.headers.get("X-DN") === "1";
}
async function body(req){
  const t = await req.text(); if(t.length > MAX_CODE + 10000) throw Object.assign(new Error("too_big"), { status: 413 });
  try{ return JSON.parse(t || "{}"); }catch(e){ throw Object.assign(new Error("bad_json"), { status: 400 }); }
}
// Counts per key in a time window (sign-ups and wrong passwords per connection).
async function overLimit(db, k, max, windowMs){
  const now = Date.now();
  const r = await db.prepare(`INSERT INTO hits (k, n, until) VALUES (?1, 1, ?2)
      ON CONFLICT(k) DO UPDATE SET n = CASE WHEN until < ?3 THEN 1 ELSE n + 1 END, until = CASE WHEN until < ?3 THEN ?2 ELSE until END
      RETURNING n`).bind(k, now + windowMs, now).first();
  return r.n > max;
}
const pub = u => ({ id: u.id, login: u.login, name: u.name, island: u.island, fruit: u.fruit, admin: u.role === "admin", mustChange: !!u.must_change, created: u.created });

async function currentUser(req, env, url){
  const tok = readCookie(req, cookieName(url)); if(!tok || tok.length > 100) return null;
  const now = Date.now(), h = await sha256(tok);
  const u = await env.DB.prepare(`SELECT u.*, s.expires AS s_exp, s.hash AS s_hash FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.hash = ?`).bind(h).first();
  if(!u || u.s_exp < now || u.banned) return null;
  if(u.s_exp - now < (SESSION_DAYS - 7) * DAY || now - u.seen > DAY){   // slide the session and note the visit, at most about once a day
    await env.DB.batch([
      env.DB.prepare(`UPDATE sessions SET expires = ? WHERE hash = ?`).bind(now + SESSION_DAYS * DAY, h),
      env.DB.prepare(`UPDATE users SET seen = ? WHERE id = ?`).bind(now, u.id),
    ]);
  }
  return u;
}
async function newSession(env, url, userId){
  const tok = rand(32), now = Date.now();
  await env.DB.prepare(`INSERT INTO sessions (hash, user_id, created, expires) VALUES (?, ?, ?, ?)`).bind(await sha256(tok), userId, now, now + SESSION_DAYS * DAY).run();
  if(Math.random() < 0.05) await env.DB.prepare(`DELETE FROM sessions WHERE expires < ?`).bind(now).run();
  return sessionCookie(url, tok, SESSION_DAYS * 86400);
}

/* ---------- routes ---------- */
export async function onRequest(ctx){
  const { request: req, env } = ctx;
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");
  const m = req.method;
  try{
    if(path === "status") return json({ ready: !!env.DB });
    if(!env.DB) return fail("no_db", 503);
    await setup(env.DB);
    const db = env.DB;
    if(m === "GET" && path === "me"){ const u = await currentUser(req, env, url); return json({ user: u ? pub(u) : null }); }
    if(m === "GET" && path === "sync") return getSync(req, env, url);
    if(m !== "GET" && !sameSite(req, url)) return fail("origin", 403);
    const ip = req.headers.get("CF-Connecting-IP") || "local";

    if(m === "POST" && path === "signup"){
      const b = await body(req);
      const login = cleanText(b.login).toLowerCase(), name = cleanText(b.name), island = cleanText(b.island), fruit = FRUITS.includes(b.fruit) ? b.fruit : "";
      if(!okLogin(login)) return fail("login_rule");
      if(!okPw(b.pw)) return fail("pw_rule");
      if(!okName(name) || !okName(island)) return fail("name_rule");
      if(await overLimit(db, "su:" + ip, 5, 3600000)) return fail("slow_down", 429);
      const id = rand(9), now = Date.now();
      try{
        await db.prepare(`INSERT INTO users (id, login, pw, name, island, fruit, role, created, seen)
            VALUES (?, ?, ?, ?, ?, ?, CASE WHEN (SELECT COUNT(*) FROM users) = 0 THEN 'admin' ELSE '' END, ?, ?)`)
          .bind(id, login, await hashPw(b.pw), name, island, fruit, now, now).run();
      }catch(e){ if(/UNIQUE/i.test(String(e.message))) return fail("login_taken", 409); throw e; }
      const u = await db.prepare(`SELECT * FROM users WHERE id = ?`).bind(id).first();
      return json({ user: pub(u) }, 200, { "Set-Cookie": await newSession(env, url, id) });
    }

    if(m === "POST" && path === "login"){
      const b = await body(req), login = cleanText(b.login).toLowerCase(), now = Date.now();
      if(await overLimit(db, "li:" + ip, 30, 600000)) return fail("slow_down", 429);
      const u = okLogin(login) ? await db.prepare(`SELECT * FROM users WHERE login = ?`).bind(login).first() : null;
      if(!u){ await checkPw(String(b.pw || ""), "p2$" + PBKDF2_ITER + "$AAAAAAAAAAAAAAAAAAAAAA$AAAA"); return fail("wrong", 401); }
      if(u.banned) return fail("banned", 403);
      if(u.lock_until > now) return fail("locked", 429, { wait: Math.ceil((u.lock_until - now) / 60000) });
      if(!(await checkPw(String(b.pw || ""), u.pw))){
        const fails = u.fails + 1;
        await db.prepare(`UPDATE users SET fails = ?, lock_until = ? WHERE id = ?`).bind(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? now + LOCK_MS : 0, u.id).run();
        return fail(fails >= MAX_FAILS ? "locked" : "wrong", fails >= MAX_FAILS ? 429 : 401, fails >= MAX_FAILS ? { wait: LOCK_MS / 60000 } : {});
      }
      await db.prepare(`UPDATE users SET fails = 0, lock_until = 0, seen = ? WHERE id = ?`).bind(now, u.id).run();
      return json({ user: pub(u) }, 200, { "Set-Cookie": await newSession(env, url, u.id) });
    }

    if(m === "POST" && path === "logout"){
      const tok = readCookie(req, cookieName(url));
      if(tok) await db.prepare(`DELETE FROM sessions WHERE hash = ?`).bind(await sha256(tok)).run();
      return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(url, "", 0) });
    }

    // Everything below needs a signed-in person.
    const u = await currentUser(req, env, url);
    if(!u) return fail("signin", 401);

    if(m === "POST" && path === "me"){
      const b = await body(req), name = cleanText(b.name), island = cleanText(b.island), fruit = FRUITS.includes(b.fruit) ? b.fruit : "";
      if(!okName(name) || !okName(island)) return fail("name_rule");
      await db.prepare(`UPDATE users SET name = ?, island = ?, fruit = ? WHERE id = ?`).bind(name, island, fruit, u.id).run();
      return json({ user: pub({ ...u, name, island, fruit }) });
    }

    if(m === "POST" && path === "password"){
      const b = await body(req);
      if(!okPw(b.pw)) return fail("pw_rule");
      if(!(await checkPw(String(b.old || ""), u.pw))) return fail("wrong", 401);
      await db.batch([
        db.prepare(`UPDATE users SET pw = ?, must_change = 0 WHERE id = ?`).bind(await hashPw(b.pw), u.id),
        db.prepare(`DELETE FROM sessions WHERE user_id = ? AND hash <> ?`).bind(u.id, u.s_hash),   // other devices sign in again
      ]);
      return json({ user: pub({ ...u, must_change: 0 }) });
    }

    if(m === "POST" && path === "leave"){
      const b = await body(req);
      if(!(await checkPw(String(b.pw || ""), u.pw))) return fail("wrong", 401);
      if(u.role === "admin" && (await db.prepare(`SELECT COUNT(*) AS n FROM users`).first()).n > 1) return fail("admin_last", 409);
      await db.batch([
        db.prepare(`DELETE FROM sync WHERE user_id = ?`).bind(u.id),
        db.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(u.id),
        db.prepare(`DELETE FROM users WHERE id = ?`).bind(u.id),
      ]);
      return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(url, "", 0) });
    }

    if(m === "PUT" && path === "sync"){
      const b = await body(req), code = String(b.code || ""), base = Math.max(0, Math.floor(+b.base || 0)), now = Date.now();
      if(!/^AC[01]\.[A-Za-z0-9_-]+$/.test(code) || code.length > MAX_CODE) return fail("bad_code");
      const r = base === 0
        ? await db.prepare(`INSERT INTO sync (user_id, rev, code, updated) VALUES (?, 1, ?, ?) ON CONFLICT(user_id) DO NOTHING`).bind(u.id, code, now).run()
        : await db.prepare(`UPDATE sync SET rev = rev + 1, code = ?, updated = ? WHERE user_id = ? AND rev = ?`).bind(code, now, u.id, base).run();
      if(!r.meta.changes){ const cur = await db.prepare(`SELECT rev, code, updated FROM sync WHERE user_id = ?`).bind(u.id).first(); return fail("conflict", 409, cur || { rev: 0 }); }
      return json({ rev: base + 1, updated: now });
    }

    if(path.startsWith("admin/")){
      if(u.role !== "admin") return fail("not_admin", 403);
      if(m === "GET" && path === "admin/users"){
        const r = await db.prepare(`SELECT id, login, name, island, fruit, role, must_change, created, seen, banned FROM users ORDER BY created`).all();
        return json({ users: r.results.map(x => ({ ...pub(x), seen: x.seen, banned: !!x.banned })) });
      }
      if(m === "POST" && path === "admin/reset"){
        const b = await body(req), t = await db.prepare(`SELECT id, role FROM users WHERE id = ?`).bind(String(b.id || "")).first();
        if(!t) return fail("no_user", 404);
        if(t.id === u.id) return fail("self");
        const ABC = "abcdefghjkmnpqrstuvwxyz23456789", bytes = crypto.getRandomValues(new Uint8Array(10));
        const temp = [...bytes].map(x => ABC[x % ABC.length]).join("");
        await db.batch([
          db.prepare(`UPDATE users SET pw = ?, must_change = 1, fails = 0, lock_until = 0 WHERE id = ?`).bind(await hashPw(temp), t.id),
          db.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(t.id),
        ]);
        return json({ temp });
      }
    }
    return fail("not_found", 404);
  }catch(e){
    if(e && e.status) return fail(e.message, e.status);
    return fail("server", 500, { detail: String((e && e.message) || e).slice(0, 200) });
  }
}

async function getSync(req, env, url){
  const u = await currentUser(req, env, url); if(!u) return fail("signin", 401);
  const r = await env.DB.prepare(`SELECT rev, code, updated FROM sync WHERE user_id = ?`).bind(u.id).first();
  return json(r || { rev: 0 });
}
