// 도란도란 동물의숲 server (Cloudflare Pages Functions): own sign-in (login id + password), profile, check-record sync,
// trade posts (구해요 / 팔아요 / 나눔) with comments.
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
  `CREATE TABLE IF NOT EXISTS posts (
     id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type TEXT NOT NULL, items TEXT NOT NULL, pay TEXT NOT NULL,
     body TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open', cmts INTEGER NOT NULL DEFAULT 0,
     created INTEGER NOT NULL, updated INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS posts_status ON posts(status, updated)`,
  `CREATE INDEX IF NOT EXISTS posts_user ON posts(user_id, updated)`,
  `CREATE TABLE IF NOT EXISTS comments (id TEXT PRIMARY KEY, post_id TEXT NOT NULL, user_id TEXT NOT NULL, body TEXT NOT NULL, created INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS comments_post ON comments(post_id, created)`,
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
/* ---------- trade posts ---------- */
const TYPES = ["want", "sell", "free"];
const SERVICES = ["turnip", "shop", "catalog", "help"];   // 무 섬 입장, 상점 구경, 만지작(카탈로그 등록), 그 밖의 부탁
// No cash trades: bank words, pay apps, gift cards, and "number + 원".
const CASH = /(계좌|입금|송금|현금|현거래|현질|(?<![가-힣])토스(?![터트])|카카오\s*페이|카페이|네이버\s*페이|페이코|문상|문화\s*상품권|컬[쳐처]\s*랜드|해피\s*머니|기프티콘|기프트\s*카드|상품권|페이팔|paypal|venmo|₩|krw|\d[\d,.\s]*(만|천)?\s*원(?!하|해|할|함|했|합|래|룸|피스|목|석|숭이|두|형|예|반|통|뿔|탁|더|소|심|시|승|\s*포인트)|만\s*원(?!하|해|할|함|했|합))/i;
// Post text keeps line breaks (at most one empty line in a row); everything else like cleanText.
const cleanBody = (s, max) => String(s ?? "").normalize("NFC").replace(/\r\n?/g, "\n").replace(/[\u0000-\u0009\u000b-\u001f\u007f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g, "").split("\n").map(l => l.replace(/\s+/g, " ").trim()).join("\n").replace(/\n{3,}/g, "\n\n").trim().slice(0, max);
const hasCash = (...t) => t.some(x => x && CASH.test(String(x)));
const intIn = (v, lo, hi) => { const n = Math.floor(Number(v)); return Number.isFinite(n) && n >= lo && n <= hi ? n : null; };
function cleanItems(arr){
  if(!Array.isArray(arr) || !arr.length || arr.length > 20) return null;
  const out = [], seen = new Set();
  for(const x of arr){
    if(!x || typeof x !== "object") return null;
    let o;
    if(x.k === "i"){ const id = intIn(x.id, 0, 9999999); if(id === null) return null; o = { k: "i", id, n: intIn(x.n, 1, 999) || 1 }; const c = intIn(x.c, 0, 63); if(c !== null) o.c = c; }
    else if(x.k === "v"){ const id = String(x.id || ""); if(!/^[A-Za-z0-9_.-]{1,32}$/.test(id)) return null; o = { k: "v", id, m: x.m === "photo" ? "photo" : "move" }; }
    else if(x.k === "s"){ if(!SERVICES.includes(x.id)) return null; o = { k: "s", id: x.id }; }
    else return null;
    const key = o.k + ":" + o.id + ":" + (o.c ?? "") + ":" + (o.m || "");
    if(seen.has(key)) continue; seen.add(key); out.push(o);
  }
  return out;
}
function cleanPay(p, type){
  if(type === "free") return { free: true };
  p = p && typeof p === "object" ? p : {};
  const o = {}, mile = intIn(p.mile, 1, 999), bells = intIn(p.bells, 1, 999999999), swap = cleanText(p.swap).slice(0, 100);
  if(mile) o.mile = mile; if(bells) o.bells = bells; if(swap) o.swap = swap; if(p.nego) o.nego = true;
  return Object.keys(o).length ? o : null;
}
const author = r => ({ id: r.user_id, name: r.a_name || "", island: r.a_island || "", fruit: r.a_fruit || "" });
const postOut = r => ({ id: r.id, type: r.type, items: JSON.parse(r.items), pay: JSON.parse(r.pay), body: r.body, status: r.status, cmts: r.cmts, created: r.created, updated: r.updated, author: author(r) });
const POST_SQL = `SELECT p.*, u.name AS a_name, u.island AS a_island, u.fruit AS a_fruit FROM posts p JOIN users u ON u.id = p.user_id WHERE u.banned = 0`;
async function postInput(b){
  const type = TYPES.includes(b.type) ? b.type : null; if(!type) return { err: "type" };
  const items = cleanItems(b.items); if(!items) return { err: "items" };
  const pay = cleanPay(b.pay, type); if(!pay) return { err: "pay" };
  const body = cleanBody(b.body, 500);
  if(hasCash(body, pay.swap)) return { err: "cash" };
  return { type, items, pay, body };
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
    if(m === "GET" && path === "posts"){
      const mine = url.searchParams.get("mine") === "1", before = intIn(url.searchParams.get("before"), 1, 9e15);
      let r;
      if(mine){
        const u = await currentUser(req, env, url); if(!u) return fail("signin", 401);
        r = await db.prepare(POST_SQL + ` AND p.user_id = ? AND p.updated < ? ORDER BY p.updated DESC LIMIT 100`).bind(u.id, before || 9e15).all();
      } else r = await db.prepare(POST_SQL + ` AND p.status = 'open' AND p.updated < ? ORDER BY p.updated DESC LIMIT 200`).bind(before || 9e15).all();
      return json({ posts: r.results.map(postOut), more: r.results.length >= (mine ? 100 : 200) });
    }
    let pm;
    if(m === "GET" && (pm = /^posts\/([A-Za-z0-9_-]{6,24})$/.exec(path))){
      const r = await db.prepare(POST_SQL + ` AND p.id = ?`).bind(pm[1]).first();
      if(!r) return fail("no_post", 404);
      const c = await db.prepare(`SELECT c.id, c.body, c.created, c.user_id, u.name AS a_name, u.island AS a_island, u.fruit AS a_fruit FROM comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = ? AND u.banned = 0 ORDER BY c.created LIMIT 300`).bind(pm[1]).all();
      return json({ post: postOut(r), comments: c.results.map(x => ({ id: x.id, body: x.body, created: x.created, author: author(x) })) });
    }
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
        db.prepare(`UPDATE posts SET cmts = MAX(0, cmts - (SELECT COUNT(*) FROM comments c WHERE c.post_id = posts.id AND c.user_id = ?))`).bind(u.id),
        db.prepare(`DELETE FROM comments WHERE user_id = ? OR post_id IN (SELECT id FROM posts WHERE user_id = ?)`).bind(u.id, u.id),
        db.prepare(`DELETE FROM posts WHERE user_id = ?`).bind(u.id),
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

    if(m === "POST" && path === "posts"){
      const v = await postInput(await body(req)); if(v.err) return fail(v.err);
      if(await overLimit(db, "po:" + u.id, 30, DAY)) return fail("slow_down", 429);
      const id = rand(9), now = Date.now();
      await db.prepare(`INSERT INTO posts (id, user_id, type, items, pay, body, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(id, u.id, v.type, JSON.stringify(v.items), JSON.stringify(v.pay), v.body, now, now).run();
      return json({ post: postOut({ id, user_id: u.id, ...v, items: JSON.stringify(v.items), pay: JSON.stringify(v.pay), status: "open", cmts: 0, created: now, updated: now, a_name: u.name, a_island: u.island, a_fruit: u.fruit }) });
    }
    if((pm = /^posts\/([A-Za-z0-9_-]{6,24})(\/comments)?$/.exec(path))){
      const p = await db.prepare(`SELECT * FROM posts WHERE id = ?`).bind(pm[1]).first();
      if(!p) return fail("no_post", 404);
      const own = p.user_id === u.id, admin = u.role === "admin", now = Date.now();
      if(pm[2]){
        if(m !== "POST") return fail("not_found", 404);
        const b = await body(req), text = cleanBody(b.body, 300);
        if(!text) return fail("empty");
        if(hasCash(text)) return fail("cash");
        if(await overLimit(db, "cm:" + u.id, 200, DAY)) return fail("slow_down", 429);
        const id = rand(9);
        await db.batch([
          db.prepare(`INSERT INTO comments (id, post_id, user_id, body, created) VALUES (?, ?, ?, ?, ?)`).bind(id, p.id, u.id, text, now),
          db.prepare(`UPDATE posts SET cmts = cmts + 1 WHERE id = ?`).bind(p.id),
        ]);
        return json({ comment: { id, body: text, created: now, author: { id: u.id, name: u.name, island: u.island, fruit: u.fruit } } });
      }
      if(m === "DELETE"){
        if(!own && !admin) return fail("not_yours", 403);
        await db.batch([db.prepare(`DELETE FROM comments WHERE post_id = ?`).bind(p.id), db.prepare(`DELETE FROM posts WHERE id = ?`).bind(p.id)]);
        return json({ ok: true });
      }
      if(m === "POST"){
        if(!own) return fail("not_yours", 403);
        const b = await body(req);
        if(b.status && !b.items){
          if(!["open", "done"].includes(b.status)) return fail("status");
          await db.prepare(`UPDATE posts SET status = ?, updated = ? WHERE id = ?`).bind(b.status, now, p.id).run();
        } else {
          const v = await postInput(b); if(v.err) return fail(v.err);
          await db.prepare(`UPDATE posts SET type = ?, items = ?, pay = ?, body = ?, updated = ? WHERE id = ?`).bind(v.type, JSON.stringify(v.items), JSON.stringify(v.pay), v.body, now, p.id).run();
        }
        const r = await db.prepare(POST_SQL + ` AND p.id = ?`).bind(p.id).first();
        return json({ post: postOut(r) });
      }
    }
    if(m === "DELETE" && (pm = /^comments\/([A-Za-z0-9_-]{6,24})$/.exec(path))){
      const c = await db.prepare(`SELECT * FROM comments WHERE id = ?`).bind(pm[1]).first();
      if(!c) return fail("no_comment", 404);
      if(c.user_id !== u.id && u.role !== "admin"){
        const p = await db.prepare(`SELECT user_id FROM posts WHERE id = ?`).bind(c.post_id).first();
        if(!p || p.user_id !== u.id) return fail("not_yours", 403);   // the post's author may tidy comments on their own post
      }
      await db.batch([db.prepare(`DELETE FROM comments WHERE id = ?`).bind(c.id), db.prepare(`UPDATE posts SET cmts = MAX(0, cmts - 1) WHERE id = ?`).bind(c.post_id)]);
      return json({ ok: true });
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
