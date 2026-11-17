// 도란도란 동물의숲: 휴대폰 알림만 맡는 작은 일꾼이에요. 페이지나 그림을 따로 저장(캐시)하지 않아요.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

const wins = () => self.clients.matchAll({ type: "window", includeUncontrolled: true });

self.addEventListener("push", e => {
  let d = {};
  try{ d = e.data ? e.data.json() : {}; }catch(err){ d = { b: e.data ? e.data.text() : "" }; }
  e.waitUntil((async () => {
    await self.registration.showNotification(d.t || "도란도란 동물의숲", {
      body: d.b || "", icon: "/icon-192.png", badge: "/badge-96.png", lang: "ko", tag: d.id || "dn", timestamp: d.at || Date.now(), data: d });
    try{ if(self.navigator.setAppBadge){ if(d.n) await self.navigator.setAppBadge(d.n); else if(d.n === 0) await self.navigator.clearAppBadge(); } }catch(err){}
    for(const c of await wins()) c.postMessage({ dn: "notif-new" });   // an open page updates its bell at once
  })());
});

// Tapping a notice opens that post at that comment: in the open page if there is one, otherwise a new one.
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const d = e.notification.data || {};
  const q = d.ref ? [d.on, d.ref, d.cmt, d.id].join(".") : "";
  e.waitUntil((async () => {
    const c = (await wins()).find(x => new URL(x.url).origin === self.location.origin);
    if(c){ try{ await c.focus(); }catch(err){} if(q) c.postMessage({ dn: "notif-open", q }); return; }
    await self.clients.openWindow("/" + (q ? "?nt=" + encodeURIComponent(q) : ""));
  })());
});

// Some browsers renew a subscription by themselves; tell the site the new address so notices keep coming.
self.addEventListener("pushsubscriptionchange", e => {
  e.waitUntil((async () => {
    let sub = e.newSubscription;
    if(!sub){
      const k = (await (await fetch("/api/push/key", { cache: "no-store" })).json()).key.replace(/-/g, "+").replace(/_/g, "/");
      const key = Uint8Array.from(atob(k + "===".slice((k.length + 3) % 4)), c => c.charCodeAt(0));
      sub = await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
    }
    await fetch("/api/push/sub", { method: "POST", credentials: "same-origin", headers: { "X-DN": "1", "Content-Type": "application/json" },
      body: JSON.stringify({ ...sub.toJSON(), old: e.oldSubscription ? e.oldSubscription.endpoint : "" }) });
  })().catch(() => {}));
});
