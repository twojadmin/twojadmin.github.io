/* ================= daty i formaty ================= */
const DAY = 86400000, YEAR = 365.25 * DAY, MON = 30.44 * DAY;
const D = s => new Date(s + "T00:00:00Z").getTime();
const fmt = t => new Date(t).toISOString().slice(0, 10);
const fmtM = t => { const d = new Date(t); return String(d.getUTCMonth() + 1).padStart(2, "0") + "." + d.getUTCFullYear(); };
function addMonths(t, n) { const d = new Date(t); const w = Math.floor(n); d.setUTCMonth(d.getUTCMonth() + w); return d.getTime() + (n - w) * MON; }
const nf = new Intl.NumberFormat("pl-PL", { maximumFractionDigits: 0 });
const nf1 = new Intl.NumberFormat("pl-PL", { maximumFractionDigits: 1 });
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const attr = html => html.replace(/"/g, "&quot;");
const trunc = (s, n) => s.length > n ? s.slice(0, Math.max(1, n - 1)) + "…" : s;

/* ================= dane (ładowane z data/*.json) ================= */
// wersja strony z adresu skryptu (index.html: assets/app.js?v=…) — ta sama wersja dla modułów pomocniczych, aby ominąć stare pliki w pamięci podręcznej
const APP_VERSION = new URL(import.meta.url).searchParams.get("v") || "dev";
const { syncLifecycle, formatJson } = await import("./datasync.js?v=" + encodeURIComponent(APP_VERSION));
// Katalog produktów, daty wsparcia i podatności są w data/*.json — tutaj tylko je wczytujemy.
let FAM = {}, OS_CARDS = [], GROUPS = [], TPL = [], CAT_NAMES = {}, CAT_DEF = {}, LIC_N = {}, JAVAS = [], DATA = {};
const DATA_FILES = ["products", "lifecycle", "vulnerabilities"];
const OVR_KEY = n => "supsim-data-" + n;
function readOverride(n) { try { return JSON.parse(localStorage.getItem(OVR_KEY(n)) || "null"); } catch (e) { return null; } }
function writeOverride(n, obj) { try { if (obj) localStorage.setItem(OVR_KEY(n), JSON.stringify(obj)); else localStorage.removeItem(OVR_KEY(n)); return true; } catch (e) { return false; } }
async function loadData() {
  const out = { local: {} };
  for (const n of DATA_FILES) {
    const r = await fetch(`data/${n}.json`, { cache: "no-cache" });
    if (!r.ok) throw new Error(`data/${n}.json: HTTP ${r.status}`);
    out[n] = await r.json(); out.server = out.server || {}; out.server[n] = out[n];
    const ovr = readOverride(n); if (ovr) { out[n] = ovr; out.local[n] = true; }
  }
  return out;
}
function channelLic(a, b) {
  if (a.ch === "pro" && b.ch === "pro") return ["free", "Bezpłatna aktualizacja wersji Pro (wymaga zgodnego sprzętu)."];
  if (a.ch !== b.ch) return ["buy", "Zmiana kanału (" + a.ch + " → " + b.ch + ") — nowa licencja."];
  return ["buy", "Nowa wersja LTSC — licencja zbiorcza lub Software Assurance."];
}
function buildFam(d) {
  DATA = d;
  const P = d.products, L = d.lifecycle.families || {}, Vf = (d.vulnerabilities && d.vulnerabilities.families) || {};
  FAM = {};
  for (const [k, m] of Object.entries(P.families)) {
    if (!L[k] || !L[k].length) { console.warn("Brak wersji w lifecycle.json dla", k); continue; }
    const F = { ...m };
    F.v = L[k].map(x => ({ ...x, eol: x.eol || x.eos }));
    F.breaks = m.breaksFrom ? (P.families[m.breaksFrom].breaks || []) : (m.breaks || []);
    F.lic = m.lic || "free";
    const vv = Vf[k] || {}; F.cve = vv.rate != null ? vv.rate : 2; F.kevData = vv.kev || null;
    if (m.jump) F.jump = i => { const l = F.v[i] && F.v[i].l; return (m.jump.from && m.jump.from[l]) || m.jump.default; };
    if (m.licByChannel) F.licOf = channelLic;
    FAM[k] = F;
  }
  OS_CARDS = P.osCards.filter(c => FAM[c.f]); GROUPS = P.groups.map(([g, fs]) => [g, fs.filter(f => FAM[f])]);
  TPL = P.templates; CAT_NAMES = P.categories; CAT_DEF = P.genericSupportYears; LIC_N = P.licenseModels; JAVAS = P.javaRuntimes.filter(f => FAM[f]);
}
const cardFilt = k => { const c = OS_CARDS.find(x => x.k === k); return c && c.pre ? (x => x.l.startsWith(c.pre)) : null; };
const cardOf = (f, l) => (OS_CARDS.find(c => c.f === f && (!c.pre || (l || "").startsWith(c.pre))) || OS_CARDS.find(c => c.f === f) || OS_CARDS[0]).k;

/* ================= pomocnicze dla wersji ================= */
const famV = (f, l) => FAM[f] ? FAM[f].v.findIndex(x => x.l === l) : -1;
function recIdx(f, t0, filt) {
  const vs = FAM[f].v; let b = -1;
  vs.forEach((x, i) => { if (filt && !filt(x)) return; if (D(x.rel) <= t0 && !x.norec && (b < 0 || D(x.eos) >= D(vs[b].eos))) b = i; });
  if (b < 0) vs.forEach((x, i) => { if (!filt || filt(x)) b = i; });
  return b < 0 ? vs.length - 1 : b;
}
function oldIdx(f, t0, filt) { const i = famV(f, FAM[f].old); if (i >= 0 && (!filt || filt(FAM[f].v[i]))) return i; const j = FAM[f].v.findIndex(x => !filt || filt(x)); return j >= 0 ? j : Math.max(0, recIdx(f, t0) - 2); }
// cel modernizacji: najlepsza wersja w tym samym kanale (Pro/LTSC/IoT), jeśli taki istnieje
function tgtIdx(f, cur, t0) { const ch = FAM[f].v[cur] && FAM[f].v[cur].ch; const i = ch ? recIdx(f, t0, x => x.ch === ch) : recIdx(f, t0); return FAM[f].v[i] && (!ch || FAM[f].v[i].ch === ch) ? i : recIdx(f, t0); }
const stOf = (eos, eol, t) => t < eos ? "full" : t < eol ? "ext" : "eol";
const ST_N = { full: "pełne wsparcie", ext: "tylko poprawki bezp. / rozszerzone", eol: "po EOL — brak poprawek", nopatch: "edycja bez wsparcia — brak poprawek bezpieczeństwa" };
const ST_S = { full: "wspierana", ext: "rozszerzone", eol: "po EOL", nopatch: "bez poprawek" };
const ST_C = { full: "var(--good)", ext: "var(--warning)", eol: "var(--critical)", nopatch: "var(--critical)" };
// edycje, które nigdy nie dostają poprawek (np. Oracle XE / Free): flaga noPatches w products.json lub nopatch przy wersji
const isNoPatch = (f, x) => !!(FAM[f] && (FAM[f].noPatches || (x && x.nopatch)));
const verSt = (f, i, t) => { const v = FAM[f].v[i]; return isNoPatch(f, v) ? "nopatch" : stOf(D(v.eos), D(v.eol), t); };
const compSt = (c, t) => isNoPatch(c.fam, FAM[c.fam] && FAM[c.fam].v[c.vi]) ? "nopatch" : stOf(D(c.eos), D(c.eol), t);
function breaksBetween(f, a, b) { const F = FAM[f]; return (F.breaks || []).filter(x => { const i = famV(f, x.at); return i > a && i <= b; }); }
function route(f, a, b) {
  const F = FAM[f], out = []; let cur = a, g = 0;
  while (cur < b && g++ < 20) {
    let n;
    if (F.stepwise) n = cur + 1;
    else if (F.jump) n = Math.min(b, cur + F.jump(cur));
    else if (F.via) { const vs = F.via.map(l => famV(f, l)).filter(i => i > cur && i < b); n = vs.length ? Math.min(...vs) : b; }
    else n = b;
    out.push(n); cur = n;
  }
  return out;
}
function mkVer(F, x, over) {
  const v = { label: x ? x.l : over.label, eos: over && over.eos != null ? over.eos : D(x.eos), eol: over && over.eol != null ? over.eol : D(x.eol), fc: x ? !!x.fc : true,
    paidExt: F && F.paidExt && x ? F.paidExt : null, esu: over && over.esu !== undefined ? over.esu : x && x.esu ? D(x.esu) : null, esuName: F ? F.esuName : null, paidAll: F && x ? F.paidAll || null : null, ch: x ? x.ch || null : over && over.ch || null,
    nopatch: !!(F && x && (F.noPatches || x.nopatch)) };
  v.eol = Math.max(v.eol, v.eos);
  return v;
}
const patchEnd = (v, buy) => v.nopatch ? -Infinity : buy ? Math.max(v.eol, v.esu || 0) : v.paidExt ? v.eos : v.eol;
function compVer(c) { const F = FAM[c.fam]; return mkVer(F, F && F.v[c.vi], { label: c.ver, eos: D(c.eos), eol: D(c.eol), esu: c.esu !== undefined ? (c.esu ? D(c.esu) : null) : undefined }); }
// IIS i podobne: wersja i wsparcie wynikają z systemu operacyjnego
const followsOs = c => !!(FAM[c.fam] && FAM[c.fam].followsOs);
function osLinkedLabel(f, osFam, osLabel) {
  if (f !== "iis") return null;
  if (osFam === "winsrv") return osLabel === "2008 R2" ? "7.5" : osLabel === "2012 R2" ? "8.5" : "10";
  return "10";
}
const isWinOs = f => FAM[f] && FAM[f].os === "win";
const famAllowed = (f, osF) => FAM[f].os === "any" || FAM[f].os === FAM[osF].os;

/* ================= stan kreatora ================= */
const $ = id => document.getElementById(id);
let W = null;      // stan szybkiej analizy
let comps = [];    // składniki do symulacji
let uid = 1;
function defaultW() {
  const t0 = D(todayStr());
  return { alts: {}, migOv: {}, buy: "yes", scen: "new", oldMode: "plan", strat: "inplace", lastPatch: fmt(addMonths(t0, -36)), tpl: "javaee", os: { f: "rhel", v: null }, sel: {} };
}
function todayStr() { return new Date().toISOString().slice(0, 10); }
function startT() { return D($("start").value || todayStr()); }
function applyTemplate(k) {
  const t = TPL.find(x => x.k === k); if (!t) return;
  W.tpl = k; W.os = { f: t.os[0], v: t.os[1] }; W.sel = {}; W.migOv = {};
  t.c.forEach(([f, v]) => W.sel[f] = v);
  if (W.scen === "new") toLatest();
}
function toLatest() {
  const t0 = startT();
  W.os.v = FAM[W.os.f].v[recIdx(W.os.f, t0, cardFilt(cardOf(W.os.f, W.os.v)))].l;
  for (const f in W.sel) W.sel[f] = FAM[f].v[recIdx(f, t0)].l;
}
function toOld() {
  const t = TPL.find(x => x.k === W.tpl), t0 = startT();
  if (t && t.os[0] === W.os.f) W.os.v = t.os[1]; else W.os.v = FAM[W.os.f].v[oldIdx(W.os.f, t0, cardFilt(cardOf(W.os.f, W.os.v)))].l;
  for (const f in W.sel) { const tc = t && t.c.find(x => x[0] === f); W.sel[f] = tc ? tc[1] : FAM[f].v[oldIdx(f, t0)].l; }
}

/* ---- budowa składników z kreatora ---- */
function autoDeps(f, has, osF) {
  const win = isWinOs(osF), d = [];
  const push = x => { if (x && (x === "os" || has(x))) d.push(x === "os" ? osF : x); };
  switch (f) {
    case "tomcat": case "wildfly": case "log4j": { const j = JAVAS.find(has); if (j) push(j); else push("os"); break; }
    case "httpd": push("os"); push(win ? "vcredist" : "openssl"); break;
    case "nginx": push("os"); if (!win) push("openssl"); break;
    case "php": if (has("httpd")) push("httpd"); else if (has("iis")) push("iis"); else push("os"); if (win) push("vcredist"); break;
    case "python": push("os"); if (!win) push("openssl"); break;
    default: push("os");
  }
  return [...new Set(d)];
}
function makeComp(f, label, prev) {
  const F = FAM[f]; let i = famV(f, label); if (i < 0) i = recIdx(f, startT()); const v = F.v[i];
  const c = { id: f, fam: f, vi: i, name: F.name, ver: v.l, cat: F.cat, eos: v.eos, eol: v.eol, cad: F.cad, cve: F.cve, lag: F.lag,
    upd: F.h[0], test: F.h[1], mit: F.h[2], verh: F.h[3], mig: F.h[4], deps: [], direct: true };
  if (prev) ["cad", "cve", "lag", "upd", "test", "mit", "verh", "mig"].forEach(k => c[k] = prev[k]);
  return c;
}
function buildComps() {
  const prevMap = Object.fromEntries(comps.map(c => [c.id, c]));
  const custom = comps.filter(c => c.fam === "custom");
  const osF = W.os.f;
  const list = [makeComp(osF, W.os.v, prevMap[osF] && prevMap[osF].fam === osF ? prevMap[osF] : null)];
  const chosen = GROUPS.flatMap(g => g[1]).filter(f => W.sel[f] != null && famAllowed(f, osF));
  const has = f => chosen.includes(f);
  const osC = list[0], osV = FAM[osF].v[osC.vi];
  chosen.forEach(f => {
    const linked = FAM[f].followsOs ? osLinkedLabel(f, osF, osC.ver) : null;
    const c = makeComp(f, linked || W.sel[f], prevMap[f]);
    if (linked) { W.sel[f] = linked; c.ver = `${linked} (${osC.ver})`; c.eos = osC.eos; c.eol = osC.eol; c.esu = osV.esu || ""; }
    c.deps = autoDeps(f, has, osF); list.push(c);
  });
  custom.forEach(c => { c.deps = c.deps.filter(d => d === osF || has(d) || custom.some(x => x.id === d)); if (!c.deps.length) c.deps = [osF]; list.push(c); });
  // OS poprzedniego wyboru w zależnościach własnych składników
  comps = list;
  const depended = new Set(comps.flatMap(c => c.deps));
  comps.forEach(c => { if (c.cat !== "os" && c.fam !== "custom") c.direct = !depended.has(c.id) || c.cat === "db"; if (c.cat === "os") c.direct = false; });
}

/* ================= RNG ================= */
function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function hash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }

/* ================= zależności ================= */
function dependentsCount() {
  const rev = {}; comps.forEach(c => rev[c.id] = []);
  comps.forEach(c => c.deps.forEach(d => rev[d] && rev[d].push(c.id)));
  const out = {};
  comps.forEach(c => { const seen = new Set(), st = [...rev[c.id]]; while (st.length) { const x = st.pop(); if (seen.has(x)) continue; seen.add(x); st.push(...rev[x]); } out[c.id] = seen.size + 1; });
  return out;
}
function topo() {
  const out = [], seen = new Set();
  const visit = c => { if (!c || seen.has(c.id)) return; seen.add(c.id); c.deps.forEach(d => visit(comps.find(x => x.id === d))); out.push(c); };
  comps.filter(c => c.cat === "os").forEach(visit); comps.forEach(visit);
  return out;
}

/* ================= plan modernizacji (stary serwer) ================= */
const famShort = f => FAM[f].name.replace(/ \(.*\)$/, "").replace(/ \/ .*$/, "");
const paramsOf = F => ({ cad: F.cad, cve: F.cve, lag: F.lag, upd: F.h[0], test: F.h[1], mit: F.h[2], verh: F.h[3], mig: F.h[4] });
const paramsOfComp = c => ({ cad: c.cad, cve: c.cve, lag: c.lag, upd: c.upd, test: c.test, mit: c.mit, verh: c.verh, mig: c.mig });
// wybrany darmowy odpowiednik dla składnika (lub null)
// ręczne ustawienia migracji: W.migOv[id] = { at: "RRRR-MM-01" (data go‑live), h: godziny migracji }
const migOvOf = c => (W.migOv && W.migOv[c.id]) || {};
const ovAt = c => { const o = migOvOf(c); return o.at ? D(o.at) : null; };
const migH = (c, base) => { const o = migOvOf(c); return o.h != null && o.h !== "" && isFinite(+o.h) ? Math.max(0, +o.h) : base; };
function altFor(c) { const F = FAM[c.fam], to = W.alts && W.alts[c.fam]; return F && to && F.alts ? F.alts.find(a => a.to === to && FAM[a.to]) || null : null; }
// wersja docelowa odpowiednika: ta sama wersja główna (np. Java 8 → Corretto 8), jeśli ma jeszcze ≥ 1 rok poprawek; inaczej zalecana
function altTargetIdx(alt, fromLabel, t) {
  const T = FAM[alt.to];
  if (alt.same) { const j = famV(alt.to, String(fromLabel).replace("*", "").split(" ")[0]); if (j >= 0 && patchEnd(mkVer(T, T.v[j]), false) > addMonths(t, 12)) return j; }
  return recIdx(alt.to, t);
}
function computePlan(p) {
  const t0 = p.start, cap = Math.max(20, p.fte * 140 * 0.6), deps = dependentsCount();
  const tf = c => 1 + p.reg * (deps[c.id] - 1);
  const order = topo();
  const tgts = {}, alts = {};
  order.forEach(c => {
    if (c.fam === "custom" || followsOs(c)) return;
    const a = altFor(c);
    if (a) { alts[c.id] = { to: a.to, i: altTargetIdx(a, c.ver, t0), alt: a }; return; }
    const ti = tgtIdx(c.fam, c.vi, t0); if (ti > c.vi) tgts[c.id] = ti;
  });
  const supported = comps.filter(c => patchEnd(compVer(c), p.buy) > t0);
  const P0 = { kind: "phase", name: "Etap 0: inwentaryzacja, analiza zgodności, triage zaległych podatności", start: t0, end: addMonths(t0, 1), hours: 8 + 4 * comps.length, notes: [] };
  const P1 = { kind: "phase", name: "Etap 1: doinstalowanie zaległych poprawek w seriach jeszcze wspieranych", start: addMonths(t0, 1), end: addMonths(t0, 2),
    hours: supported.reduce((s, c) => s + c.upd * 1.5 + c.test * tf(c), 0), notes: supported.length ? [{ s: "info", t: "Dotyczy: " + supported.map(c => c.name + " " + c.ver).join(", ") }] : [{ s: "info", t: "Żaden składnik nie jest już wspierany — poprawek brak, pozostają mitygacje." }] };
  const catchUp = addMonths(t0, 1.5);
  const steps = [], forced = {};
  let cur = addMonths(t0, 2);
  const mk = (c, name, from, to, hours, notes, extra = {}) => {
    const dur = Math.max(1, Math.ceil(hours / cap));
    const st = { kind: "step", comp: c ? c.id : null, name, from, to, start: cur, end: addMonths(cur, dur), hours, notes, ...extra };
    steps.push(st); cur = st.end; return st;
  };
  const altNotes = a => a.alt.notes.map(n => ({ ...n })).concat(FAM[a.to].mnote ? [{ s: "info", t: FAM[a.to].mnote }] : []);
  const altLabel = a => famShort(a.to) + " " + FAM[a.to].v[a.i].l;
  if (p.strat === "inplace") {
    // kolejka kroków: Oracle przechodzi na 19c przed aktualizacją systemu (stare wersje nie są certyfikowane na nowym OS)
    const queue = [];
    order.forEach(c => {
      if (alts[c.id]) { queue.push({ c, alt: alts[c.id] }); return; }
      const ti = tgts[c.id]; if (ti == null) return;
      route(c.fam, c.vi, ti).forEach((hop, k, arr) => queue.push({ c, hop, k, n: arr.length }));
    });
    const pre = queue.filter(q => !q.alt && q.c.fam === "oracle" && FAM.oracle.v[q.hop].l === "19c");
    const ordered = [...pre, ...queue.filter(q => !pre.includes(q))];
    const prevOf = {};
    ordered.forEach(q => {
      const c = q.c;
      if (q.alt) {
        const a = q.alt, mig = migH(c, a.alt.h), test = c.test * tf(c) * 3;
        const st = mk(c, "Zamiana na darmowy odpowiednik: " + c.name + " → " + FAM[a.to].name, c.ver, altLabel(a), mig + test, altNotes(a), { alt: a.to });
        (forced[c.id] = forced[c.id] || []).push({ hStart: st.start, hEnd: st.end, at: st.end, toFam: a.to, toIdx: a.i, mig, test, alt: a.alt, st });
        return;
      }
      const { hop, k, n } = q, prev = prevOf[c.id] != null ? prevOf[c.id] : c.vi, last = k === n - 1;
      const mig = migH(c, c.mig) * (last ? 1 : 0.6), test = c.test * tf(c) * 2;
      const notes = breaksBetween(c.fam, prev, hop).map(b => ({ s: b.s, t: b.t }));
      if (k === 0 && FAM[c.fam].mnote) notes.push({ s: "info", t: FAM[c.fam].mnote });
      if (!last) notes.push({ s: "info", t: "Krok pośredni wymagany przez ścieżkę aktualizacji producenta." });
      if (pre.includes(q)) notes.push({ s: "info", t: "Wykonywany przed aktualizacją systemu — 19c jest certyfikowana zarówno na starym, jak i nowym systemie." });
      const st = mk(c, "Aktualizacja w miejscu: " + c.name, FAM[c.fam].v[prev].l, FAM[c.fam].v[hop].l, mig + test, notes);
      (forced[c.id] = forced[c.id] || []).push({ hStart: st.start, hEnd: st.end, at: st.end, toIdx: hop, mig, test, st });
      prevOf[c.id] = hop;
    });
  } else {
    const os = order.find(c => c.cat === "os");
    const rec = [];
    if (os) {
      const a = alts[os.id], osT = a ? a.i : tgts[os.id] != null ? tgts[os.id] : os.vi;
      const notes = [{ s: "info", t: "Czysta instalacja — bez kroków pośrednich systemu; stary serwer działa do przełączenia." }].concat(a ? altNotes(a) : []);
      const hrs = migH(os, os.mig) * (a || tgts[os.id] != null ? 1 : 0.5) + os.test * 2;
      const st = mk(os, "Budowa nowego serwera" + (a ? " na " + FAM[a.to].name : ""), os.ver, a ? altLabel(a) : FAM[os.fam].v[osT].l, hrs, notes, a ? { alt: a.to } : {});
      rec.push([os, st, osT, a]);
    }
    order.forEach(c => {
      if (c.cat === "os" || c.fam === "custom" || followsOs(c)) return;
      const a = alts[c.id];
      if (a) {
        const st = mk(c, "Instalacja darmowego odpowiednika i migracja: " + c.name + " → " + FAM[a.to].name, c.ver, altLabel(a), migH(c, a.alt.h) * 0.8 + c.test * tf(c), altNotes(a), { alt: a.to });
        rec.push([c, st, a.i, a]); return;
      }
      const ti = tgts[c.id] != null ? tgts[c.id] : c.vi;
      const notes = breaksBetween(c.fam, c.vi, ti).map(b => ({ s: b.s, t: b.t }));
      const path = route(c.fam, c.vi, ti);
      if (path.length > 1 && c.cat === "db") notes.push({ s: "med", t: "Migracja danych wymaga ścieżki przez " + path.slice(0, -1).map(i => FAM[c.fam].v[i].l).join(" → ") + " (lub eksport/import logiczny)." });
      const hrs = migH(c, c.mig) * (ti > c.vi ? 0.8 : 0.3) + c.test * tf(c);
      const st = mk(c, (ti > c.vi ? "Instalacja nowej wersji i migracja: " : "Reinstalacja i konfiguracja: ") + c.name, c.ver, FAM[c.fam].v[ti].l, hrs, notes);
      rec.push([c, st, ti, null]);
    });
    const accHrs = comps.reduce((s, c) => s + c.test * tf(c), 0) * 1.5;
    const fin = mk(null, "Testy akceptacyjne całości i przełączenie (cut‑over)", "", "", accHrs, [{ s: "info", t: "Po przełączeniu stary serwer wyłączony; do tego czasu działa produkcyjnie i pozostaje narażony." }], { cut: true });
    rec.forEach(([c, st, ti, a]) => {
      if (a) (forced[c.id] = forced[c.id] || []).push({ hStart: st.start, hEnd: st.end, at: fin.end, toFam: a.to, toIdx: a.i, mig: 0, test: 0, alt: a.alt, st });
      else if (ti > c.vi) (forced[c.id] = forced[c.id] || []).push({ hStart: st.start, hEnd: st.end, at: fin.end, toIdx: ti, mig: 0, test: 0, st });
    });
    steps.forEach(st => st.spread = true);
  }
  // ręczna data go‑live: kroki składnika przesuwane tak, by ostatni kończył się w wybranym miesiącu
  for (const c of comps) {
    const ov = ovAt(c), fl = forced[c.id]; if (!ov || !fl || !fl.length) continue;
    let end = Math.max(ov, addMonths(t0, 1));
    for (let i = fl.length - 1; i >= 0; i--) {
      const f = fl[i], st = f.st, dur = st.end - st.start;
      st.end = end; st.start = end - dur; st.manual = true;
      f.at = f.hEnd = end; f.hStart = st.start; end = st.start;
    }
  }
  steps.sort((a, b) => a.start - b.start);
  const total = P0.hours + P1.hours + steps.reduce((s, x) => s + x.hours, 0);
  const end = steps.length ? Math.max(...steps.map(x => x.end)) : P1.end;
  return { P0, P1, steps, forced, catchUp, total, end, tgts, alts };
}

/* ================= symulacja ================= */
const SEV = [["crit", 0.12], ["high", 0.35], ["med", 0.43], ["low", 0.10]];
const SEV_F = { crit: 1.5, high: 1.2, med: 0.8, low: 0.4 };
const SEV_N = { crit: "krytyczna", high: "wysoka", med: "średnia", low: "niska" };
const SEV_C = { crit: "var(--critical)", high: "var(--serious)", med: "var(--warning)", low: "var(--low)" };
const TYPES = [["ver", "Weryfikacja podatności", "--s1"], ["mit", "Mitygacja", "--s2"], ["upd", "Aktualizacje", "--s3"], ["test", "Testy", "--s4"], ["mig", "Migracje", "--s5"]];
const pickSev = x => { let a = 0; for (const [s, pr] of SEV) { a += pr; if (x < a) return s; } return "low"; };
const kevWeight = f => 1 + ((FAM[f] && FAM[f].kevData && FAM[f].kevData.count2y) || 0) / 5;

function simulate(p, o = {}) {
  const trend = o.trend || p.trend, mode = o.mode || p.mode, buy = o.buy != null ? o.buy : p.buy;
  const t0 = p.start, tEnd = addMonths(t0, p.horizon * 12);
  const mult = t => { const y = Math.max(0, (t - t0) / YEAR); return trend === "exp" ? Math.pow(1 + p.growth, y) : trend === "lin" ? 1 + p.growth * y : 1; };
  const multMax = mult(tEnd);
  const deps = dependentsCount();
  const plan = mode === "plan" ? p.planData : null;
  const work = [], cves = [], updates = [], segs = [], migs = [], migNotes = [];
  const add = (t, c, ver, type, h, desc) => { if (h > 0 && t >= t0 && t < tEnd) work.push({ t, comp: c.id, ver, type, h, desc }); };
  const tfOf = c => 1 + p.reg * (deps[c.id] - 1);
  const spread = (a, b, c, ver, type, h, desc) => { if (h <= 0) return; a = Math.max(a, t0); if (b <= a) b = a + MON; const n = Math.max(1, Math.round((b - a) / MON)); for (let k = 0; k < n; k++) add(a + (k + 0.5) * (b - a) / n, c, ver, type, h / n, desc); };
  const mr = mulberry32((p.seed * 131 + 7) >>> 0); // losowanie skuteczności mitygacji
  // mitygacja: praca + (z prawdopodobieństwem = skuteczność) ochrona od t + czas wdrożenia
  const mitigate = (ev, c, t, h, desc) => {
    if (!p.mitOn) return;
    ev.mitig = true; add(t, c, ev.ver, "mit", h, desc);
    if (mr() < p.mitEff) ev.mitigatedAt = t + p.mitDays * DAY; else ev.mitigFail = true;
  };

  const isPaid = (v, t) => !!v.paidAll || (!!v.paidExt && t >= v.eos) || t >= v.eol;
  function handleCve(e, c, ver, seg, r, testF) {
    const { t, sev } = e, cp = seg.cp;
    const id = "SIM-" + new Date(t).getUTCFullYear() + "-" + String(1000 + Math.floor(r() * 9000));
    const supported = t < ver.pe, frozen = t < seg.frozenUntil, migrates = seg.end < tEnd;
    const ev = { t, comp: c.id, ver: ver.label, sev, id, wave: !!e.wave, backlog: !!e.backlog, supported, mitig: false, emergency: false, bundled: false, patchAt: null, closedAt: null, mitigatedAt: null };
    const nextUpd = from => seg.upd.find(x => x >= from);
    const ch = sev === "crit" || sev === "high";
    if (e.backlog) {
      if (mode === "plan") {
        add(t0 + 15 * DAY, c, ver.label, "ver", cp.verh * SEV_F[sev] * 0.5, "Triage zaległej " + id);
        if (!supported && ch) mitigate(ev, c, t0 + 20 * DAY, cp.mit * SEV_F[sev], "Mitygacja zaległej " + id + " (brak poprawki)");
      }
      const u = supported ? nextUpd(t0) : null;
      ev.closedAt = u != null ? u : migrates ? seg.end : null;
      cves.push(ev); return;
    }
    add(t, c, ver.label, "ver", cp.verh * SEV_F[sev], "Weryfikacja " + id);
    const sla = sev === "crit" ? p.slaC : p.slaH;
    if (supported) {
      const patch = t + (-Math.log(1 - r()) * cp.lag) * DAY; ev.patchAt = patch;
      if (ch && !frozen) {
        if (patch > t + sla * DAY) mitigate(ev, c, t + DAY, cp.mit * SEV_F[sev], "Mitygacja " + id + " (poprawka poza SLA)");
        const deadline = Math.max(patch, t + sla * DAY), np = nextUpd(patch);
        if (np != null && np <= deadline) { ev.bundled = true; ev.closedAt = np; }
        else if (patch < Math.min(ver.pe, seg.end)) {
          ev.emergency = true; ev.closedAt = patch;
          updates.push({ t: patch, comp: c.id, ver: ver.label, kind: "emerg", paid: isPaid(ver, patch) });
          add(patch, c, ver.label, "upd", cp.upd, "Aktualizacja awaryjna " + id);
          add(patch, c, ver.label, "test", cp.test * testF * 0.5, "Testy ukierunkowane " + id);
        } else ev.closedAt = np != null ? np : migrates ? seg.end : null;
      } else {
        if (ch && frozen) mitigate(ev, c, t + DAY, cp.mit * SEV_F[sev], "Mitygacja " + id + " (poprawki nieinstalowane)");
        const np = nextUpd(patch); ev.bundled = np != null; ev.closedAt = np != null ? np : migrates ? seg.end : null;
      }
    } else {
      if (ch) mitigate(ev, c, t + DAY, cp.mit * 1.5 * SEV_F[sev], "Mitygacja " + id + " — brak poprawek (EOL lub niewykupione wsparcie)");
      else if (sev === "med") mitigate(ev, c, t + DAY, cp.mit * 0.5, "Częściowa mitygacja " + id + " (EOL)");
      ev.closedAt = migrates ? seg.end : null;
    }
    cves.push(ev);
  }

  let osTrack = null; // przebieg systemu operacyjnego (dla składników zależnych od systemu)
  for (const c of comps) {
    const r = mulberry32((p.seed * 7919 + hash(c.id + c.name)) >>> 0);
    const testF = tfOf(c);
    let fam = c.fam, F = FAM[fam], cp = paramsOfComp(c);
    const label = (f, l) => f === c.fam ? l : famShort(f) + " " + l;
    let vi = c.fam === "custom" ? Infinity : c.vi;
    let ver = compVer(c); ver.pe = patchEnd(ver, buy);
    let forced = plan && plan.forced[c.id] && !o.noMig ? plan.forced[c.id].map(x => ({ ...x })) : [];
    // składnik zależny od systemu (IIS): migruje razem z systemem, do wersji wynikającej z nowego systemu
    if (F && F.followsOs) {
      forced = [];
      if (osTrack && !o.noMig && mode !== "noupd") osTrack.migs.forEach(m => {
        const g = osTrack.segs.find(s2 => s2.start === m.end); if (!g) return;
        const l = osLinkedLabel(c.fam, g.fam, g.label) || c.ver;
        forced.push({ at: m.end, hStart: m.start, hEnd: m.end, toVer: { ...g.ver, label: `${l} (${g.label})`, paidExt: null, paidAll: null, esuName: F.esuName || g.ver.esuName }, lab: l, mig: migH(c, cp.mig), test: cp.test * testF * 2 });
      });
    }
    // nowe wdrożenie: zamiana na odpowiednik na starcie
    let altPending = mode === "new" && !o.noMig ? altFor(c) : null;
    let frozenUntil = mode === "new" ? t0 : mode === "noupd" ? Infinity : ver.pe > t0 ? plan.catchUp : forced.length ? forced[0].at : Infinity;
    if (plan) add(t0 + 10 * DAY, c, ver.label, "ver", plan.P0.hours / comps.length, "Inwentaryzacja i analiza zgodności");
    let segStart = t0, gen = 1, guard = 0, first = true, nMig = 0;
    while (segStart < tEnd && guard++ < 30) {
      let mig = null;
      if (forced.length) mig = forced.shift();
      else if (altPending) {
        // nowe wdrożenie: odpowiednik od początku — adaptacja aplikacji przez ok. 3 miesiące, potem praca na odpowiedniku
        const at = Math.max(ovAt(c) || addMonths(t0, 3), addMonths(t0, 1));
        mig = { at, hStart: Math.max(t0, addMonths(at, -3)), hEnd: at, toFam: altPending.to, toIdx: altTargetIdx(altPending, ver.label, t0), mig: migH(c, altPending.h), test: cp.test * testF * 2, alt: altPending };
        altPending = null;
      }
      else if ((p.autoMig || (nMig === 0 && ovAt(c))) && mode !== "noupd" && !o.noMig && !ver.nopatch && !(F && F.followsOs)) {
        // migracja przed końcem dostępnych poprawek (darmowe wsparcie rozszerzone lub wykupione płatne) — albo w ręcznie wybranym miesiącu
        let at = Math.max(addMonths(ver.pe, -p.lead), addMonths(segStart, 3));
        if (first && ver.pe <= addMonths(t0, 3)) at = addMonths(t0, 3);
        if (nMig === 0 && ovAt(c)) at = Math.max(ovAt(c), addMonths(segStart, 1));
        if (at < tEnd) {
          mig = { at, hStart: Math.max(segStart, addMonths(at, -3)), hEnd: at, toIdx: "auto", mig: nMig === 0 ? migH(c, cp.mig) : cp.mig, test: cp.test * testF * 3 };
        }
      }
      const segEnd = mig && mig.at < tEnd ? mig.at : tEnd;
      const seg = { comp: c.id, fam, label: ver.label, start: segStart, end: segEnd, eos: ver.eos, eol: ver.eol, fc: ver.fc, frozenUntil, upd: [], ver, cp };
      segs.push(seg);
      if (plan && first && ver.pe > t0 && plan.catchUp < segEnd) {
        seg.upd.push(plan.catchUp); updates.push({ t: plan.catchUp, comp: c.id, ver: ver.label, kind: "catchup", paid: isPaid(ver, plan.catchUp) });
        add(plan.catchUp, c, ver.label, "upd", cp.upd * 1.5, "Doinstalowanie zaległych poprawek");
        add(plan.catchUp, c, ver.label, "test", cp.test * testF, "Testy po doinstalowaniu poprawek");
      }
      const u0 = Math.max(segStart, frozenUntil);
      if (u0 < segEnd) {
        let u = addMonths(u0, cp.cad * (0.3 + 0.7 * r()));
        while (u < segEnd && u < ver.pe) {
          seg.upd.push(u);
          updates.push({ t: u, comp: c.id, ver: ver.label, kind: u < ver.eos ? "plan" : "sec", paid: isPaid(ver, u) });
          add(u, c, ver.label, "upd", cp.upd, "Aktualizacja planowa");
          add(u, c, ver.label, "test", cp.test * testF, "Testy aktualizacji planowej");
          u = addMonths(u, cp.cad);
        }
      }
      seg.upd.sort((a, b) => a - b);
      if (first && p.scen === "old" && p.lastPatch < t0) {
        const lam = cp.cve / YEAR; let t = p.lastPatch;
        if (lam > 0) while (true) { t += -Math.log(1 - r()) / lam; if (t >= t0) break; handleCve({ t, sev: pickSev(r()), backlog: true }, c, ver, seg, r, testF); }
      }
      const lmax = cp.cve * multMax / YEAR; let t = segStart;
      if (lmax > 0) while (true) {
        t += -Math.log(1 - r()) / lmax;
        if (t >= segEnd) break;
        if (r() > (cp.cve * mult(t) / YEAR) / lmax) continue;
        handleCve({ t, sev: pickSev(r()) }, c, ver, seg, r, testF);
      }
      first = false;
      if (!mig) break;
      const desc = mig.toFam ? "Zamiana na darmowy odpowiednik" : mig.toIdx === "auto" ? "Migracja do kolejnej wersji" : "Migracja wg planu modernizacji";
      spread(mig.hStart, mig.hEnd, c, ver.label, "mig", mig.mig, desc);
      spread(mig.hStart, mig.hEnd, c, ver.label, "test", mig.test, "Pełna regresja migracji");
      if (mig.at >= tEnd) break;
      const oldI = vi, oldL = ver.label, oldFam = fam; let nv;
      if (mig.toVer) { nv = { ...mig.toVer }; vi = famV(fam, mig.lab); if (vi < 0) vi = Infinity; }
      else if (mig.toFam) {
        fam = mig.toFam; F = FAM[fam]; vi = mig.toIdx; cp = paramsOf(F);
        nv = mkVer(F, F.v[vi]); nv.label = label(fam, F.v[vi].l);
      } else if (mig.toIdx === "auto") {
        let best = -1;
        if (F && vi !== Infinity) F.v.forEach((x, j) => { if ((!ver.ch || x.ch === ver.ch) && !x.norec && j > vi && D(x.rel) <= mig.at && patchEnd(mkVer(F, x), buy) > addMonths(mig.at, 12) && (best < 0 || D(x.eos) >= D(F.v[best].eos))) best = j; });
        if (best >= 0) { vi = best; nv = mkVer(F, F.v[vi]); nv.label = label(fam, F.v[vi].l); }
        else { const [ge, gl] = F && F.gen && ver.ch ? F.gen[ver.ch] : (CAT_DEF[F ? F.cat : c.cat] || [3, 5]); vi = Infinity; nv = mkVer(null, null, { label: label(fam, "kolejna" + (gen > 1 ? " (" + gen + ")" : "") + "*"), eos: addMonths(mig.at, ge * 12), eol: addMonths(mig.at, gl * 12), ch: ver.ch }); gen++; }
      } else { vi = mig.toIdx; nv = mkVer(F, F.v[vi]); nv.label = label(fam, F.v[vi].l); }
      nv.pe = patchEnd(nv, buy);
      migs.push({ comp: c.id, from: oldL, to: nv.label, start: Math.max(mig.hStart, t0), end: mig.at, planned: mig.toIdx !== "auto", toFam: fam, alt: !!mig.toFam, manual: nMig === 0 && !!ovAt(c), withOs: !!mig.toVer });
      nMig++;
      if (mig.toFam) migNotes.push({ comp: c.id, at: mig.at, from: oldL, to: nv.label, alt: true, items: (mig.alt.notes || []).filter(n => n.s !== "info") });
      else if (F && oldI !== Infinity && vi !== Infinity && oldFam === fam) migNotes.push({ comp: c.id, at: mig.at, from: oldL, to: nv.label, items: breaksBetween(fam, oldI, vi) });
      ver = nv; segStart = mig.at; if (frozenUntil > segStart) frozenUntil = segStart;
    }
    if (c.cat === "os") osTrack = { migs: migs.filter(m => m.comp === c.id), segs: segs.filter(g => g.comp === c.id) };
  }
  // godziny planu dla strategii „nowy serwer” (rozkład w czasie kroków)
  if (plan && p.strat === "newsrv" && !o.noMig) plan.steps.forEach(st => {
    const c = st.comp ? comps.find(x => x.id === st.comp) : comps[0];
    if (!c) return;
    const sh = st.hours;
    spread(st.start, st.end, c, c.ver, st.cut ? "test" : "mig", st.cut ? sh : sh * 0.7, st.name);
    if (!st.cut) spread(st.start, st.end, c, c.ver, "test", sh * 0.3, "Testy: " + st.name);
  });
  // fale 0-day (składniki z większą liczbą wpisów w CISA KEV są częściej celem)
  if (p.waves && comps.length) {
    const wr = mulberry32((p.seed * 31 + 17) >>> 0), rate = 0.33 / YEAR; let t = t0;
    const wgt = c => c.cve * kevWeight(c.fam);
    while (true) {
      t += -Math.log(1 - wr()) / (rate * multMax);
      if (t >= tEnd) break;
      if (wr() > mult(t) / multMax) continue;
      const tot = comps.reduce((s, c) => s + wgt(c), 0); let x = wr() * tot, c = comps[0];
      for (const cc of comps) { x -= wgt(cc); if (x <= 0) { c = cc; break; } }
      const seg = segs.find(s => s.comp === c.id && t >= s.start && t < s.end); if (!seg) continue;
      comps.forEach(o2 => add(t, o2, "—", "ver", 2, "Inwentaryzacja po fali 0-day"));
      add(t + DAY, c, seg.label, "mit", seg.cp.mit * 2, "Mitygacja fali 0-day");
      handleCve({ t, sev: "crit", wave: true }, c, seg.ver, seg, wr, tfOf(c));
    }
  }
  work.sort((a, b) => a.t - b.t); cves.sort((a, b) => a.t - b.t);
  const baseRate = comps.reduce((s, c) => s + c.cve, 0) + (p.waves ? 0.33 : 0);
  return { t0, tEnd, mode, buy, work, cves, updates, segs, migs, migNotes, deps, baseRate };
}

/* ================= zgodność ================= */
function compatState(which, plan) {
  const st = { c: {} };
  comps.forEach(c => {
    if (c.fam === "custom") return;
    const a = which === "tgt" && plan && plan.alts && plan.alts[c.id];
    const f = a ? a.to : c.fam, i = a ? a.i : which === "tgt" && plan && plan.tgts[c.id] != null ? plan.tgts[c.id] : c.vi;
    st.c[f] = { i, l: FAM[f].v[i].l, name: FAM[f].name };
    if (c.cat === "os") { st.osF = f; st.osI = i; st.osL = FAM[f].v[i].l; }
  });
  if (st.osF === "almalinux") { const j = famV("rhel", st.osL); if (j >= 0) { st.osF = "rhel"; st.osI = j; } }
  return st;
}
const jv = s => { const f = JAVAS.find(x => s.c[x]); return f ? { ...s.c[f], name: FAM[f].name } : null; };
const RULES = [
  (s, A) => { ["tomcat", "wildfly"].forEach(f => { const t = s.c[f]; if (!t) return; const req = FAM[f].v[t.i].java, j = jv(s); if (!j) A("med", FAM[f].name, FAM[f].name + " wymaga Javy — dodaj OpenJDK, Oracle JDK lub JRE."); else if (req && parseInt(j.l) < parseInt(req)) A("high", FAM[f].name, `${FAM[f].name} ${t.l} wymaga Java ≥ ${req} (jest ${j.name} ${j.l}) — najpierw zaktualizuj Javę.`); }); },
  (s, A) => { if (s.c.log4j && !jv(s)) A("low", "Apache Log4j", "Log4j to biblioteka Javy — dodaj środowisko Java."); },
  (s, A) => { const n = JAVAS.filter(f => s.c[f]); if (n.length > 1) A("low", "Java", "Wybrano kilka środowisk Java (" + n.map(f => FAM[f].name).join(", ") + ") — każde wymaga osobnych aktualizacji; upewnij się, którego używa aplikacja."); },
  (s, A) => { if (s.c.java && s.c.java.l === "8") A("low", "Java (Oracle JDK)", "Oracle JDK/JRE 8 w zastosowaniach komercyjnych wymaga subskrypcji Oracle Java SE — rozważ OpenJDK."); },
  (s, A) => { const x = s.c.oraclexe; if (!x) return; A("med", "Oracle Database XE / Free", "Edycja bezpłatna bez wsparcia producenta i bez poprawek bezpieczeństwa między wydaniami — do produkcji z danymi wrażliwymi rozważ edycję płatną lub inną bazę."); if (s.osF === "ubuntu" || s.osF === "debian") A("med", "Oracle Database XE / Free", "XE/Free dla Linuksa jest dostarczana dla Oracle Linux/RHEL — na Ubuntu/Debian tylko nieoficjalnie (np. kontener)."); },
  (s, A) => { if (s.c.mssql && s.osF === "winclient") A("med", "SQL Server", "SQL Server w produkcji tylko na Windows Server — na Windows 10/11 wyłącznie edycje Developer/Express."); },
  (s, A) => { if (s.osF === "winclient" && (s.c.httpd || s.c.iis || s.c.tomcat || s.c.wildfly || s.c.oracle)) A("low", FAM.winclient.name, "System kliencki jako serwer: limit 20 jednoczesnych połączeń przychodzących (SMB/IIS), brak wsparcia producentów serwerowych — rozważ Windows Server."); },
  (s, A) => { if (s.c.log4j && s.c.log4j.l === "1.2") A("high", "Apache Log4j", "Log4j 1.x — EOL od 2015, z publicznie znanymi poważnymi podatnościami. Zastąp Log4j 2.x lub reload4j."); },
  (s, A) => { if (!isWinOs(s.osF) || !s.c.httpd || s.c.httpd.l !== "2.4") return; const v = s.c.vcredist, need = famV("vcredist", "2015–2022 (v14)"); if (!v) A("med", "Apache HTTP Server", "Apache dla Windows (kompilacje Apache Lounge, VS17) wymaga Visual C++ 2015–2022 — dodaj składnik VC++."); else if (v.i < need) A("high", "Apache HTTP Server", `Apache 2.4 dla Windows wymaga VC++ 2015–2022 — zainstalowany VC++ ${v.l} nie wystarczy.`); },
  (s, A) => { if (!isWinOs(s.osF) || !s.c.php) return; const v = s.c.vcredist, p = s.c.php; const need = p.l === "5.6" ? "2012" : "2015–2022 (v14)"; if (!v) A("med", "PHP", `PHP ${p.l} dla Windows wymaga Visual C++ ${need} — dodaj składnik VC++.`); else if (p.l === "5.6" ? v.l !== "2012" && v.i < famV("vcredist", "2012") : v.i < famV("vcredist", need)) A("high", "PHP", `PHP ${p.l} dla Windows wymaga VC++ ${need} (jest ${v.l}).`); },
  (s, A) => { if (s.c.iis && s.c.httpd) A("low", "IIS", "Apache i IIS na jednym serwerze — konflikt portów 80/443; zwykle wybiera się jeden serwer WWW lub różne porty/adresy."); },
  (s, A) => { if (s.c.iis && s.osF === "winclient") A("low", "IIS", "IIS na Windows 10/11 ma limit jednoczesnych żądań — tylko do testów; w produkcji Windows Server."); },
  (s, A) => { if (s.c.php && !s.c.httpd && !s.c.nginx && !s.c.iis) A("low", "PHP", "PHP wymaga serwera WWW (Apache z mod_php/FPM lub nginx z PHP‑FPM)."); },
  (s, A) => { if (s.c.vcredist && s.c.vcredist.i < famV("vcredist", "2015–2022 (v14)")) A("med", "Visual C++ Redistributable", `VC++ ${s.c.vcredist.l} instaluje się, ale nie dostaje już poprawek bezpieczeństwa.`); },
  (s, A) => { if (s.c.httpd && s.c.httpd.l === "2.2") A("med", "Apache HTTP Server", `Apache 2.2 nie jest dostępny w repozytoriach ${FAM[s.osF].name} ${s.osL} ani jako aktualne kompilacje — trzeba utrzymywać własną kompilację.`); },
  (s, A) => {
    const p = s.c.php; if (!p || isWinOs(s.osF)) return;
    const m = { rhel: { "7": "5.4", "8": "7.2", "9": "8.0", "10": "8.3" }, ubuntu: { "18.04": "7.2", "20.04": "7.4", "22.04": "8.1", "24.04": "8.3" }, debian: { "10": "7.3", "11": "7.4", "12": "8.2", "13": "8.4" } };
    const def = m[s.osF] && m[s.osF][s.osL];
    if (def && def !== p.l) A("low", "PHP", `PHP ${p.l} nie jest domyślną wersją w ${FAM[s.osF].name} ${s.osL} (${def}) — potrzebny moduł AppStream lub repozytorium zewnętrzne (Remi, ondrej/php, sury.org).`);
  },
  (s, A) => { const py = s.c.python; if (!py || py.l !== "2.7") return; if ((s.osF === "rhel" && s.osI >= famV("rhel", "9")) || (s.osF === "ubuntu" && s.osI >= famV("ubuntu", "24.04")) || (s.osF === "debian" && s.osI >= famV("debian", "12"))) A("high", "Python", `Python 2.7 niedostępny w repozytoriach ${FAM[s.osF].name} ${s.osL}.`); },
  (s, A) => {
    const o = s.c.openssl; if (!o || isWinOs(s.osF)) return;
    const os3 = (s.osF === "rhel" && s.osI >= famV("rhel", "9")) || (s.osF === "ubuntu" && s.osI >= famV("ubuntu", "22.04")) || (s.osF === "debian" && s.osI >= famV("debian", "12"));
    const old = (s.osF === "rhel" && s.osL === "7") || (s.osF === "ubuntu" && s.osL === "18.04") || (s.osF === "debian" && s.osL === "10");
    if (os3 && o.i < famV("openssl", "3.0 LTS")) A("med", "OpenSSL", `${FAM[s.osF].name} ${s.osL} dostarcza OpenSSL 3 — wersja ${o.l} tylko jako pakiet zgodności lub własna kompilacja, bez poprawek dystrybucji.`);
    if (old && o.i >= famV("openssl", "3.0 LTS")) A("low", "OpenSSL", `${FAM[s.osF].name} ${s.osL} nie dostarcza OpenSSL 3 — potrzebna własna kompilacja obok systemowej biblioteki.`);
  },
  (s, A) => {
    const o = s.c.oracle; if (!o) return; const os = `${FAM[s.osF].name} ${s.osL}`;
    if (s.osF === "ubuntu" || s.osF === "debian") A("med", "Oracle Database", `Oracle Database nie jest certyfikowana na ${FAM[s.osF].name} — wsparcie producenta tylko na Oracle Linux/RHEL i Windows.`);
    if ((o.l === "11gR2" || o.l === "12.2") && ((s.osF === "rhel" && s.osI >= famV("rhel", "8")) || (s.osF === "winsrv" && s.osI >= famV("winsrv", "2019")))) A("high", "Oracle Database", `Oracle ${o.l} nie jest certyfikowana na ${os} — bazę zaktualizuj przed systemem lub razem z nim.`);
    if (o.l === "19c" && s.osF === "rhel" && s.osI >= famV("rhel", "9")) A("low", "Oracle Database", "Oracle 19c na RHEL 9 wymaga Release Update ≥ 19.19 — sprawdź poziom poprawek.");
    if (o.l === "26ai" && s.osF === "rhel" && s.osL === "7") A("high", "Oracle Database", "Oracle 26ai wymaga Oracle Linux/RHEL 8 lub nowszego.");
  },
  (s, A) => {
    const m = s.c.mssql; if (!m || s.osF !== "winsrv") return; const w = s.osI;
    if ((m.l === "2012" || m.l === "2014") && w >= famV("winsrv", "2022")) A("high", "SQL Server", `SQL Server ${m.l} nie jest wspierany na Windows Server ${s.osL}.`);
    if (m.l === "2022" && w < famV("winsrv", "2016")) A("high", "SQL Server", "SQL Server 2022 wymaga Windows Server 2016 lub nowszego.");
    if (m.l === "2025" && w < famV("winsrv", "2019")) A("high", "SQL Server", "SQL Server 2025 wymaga Windows Server 2019 lub nowszego.");
    if (m.l === "2016" && s.osL === "2025") A("low", "SQL Server", "SQL Server 2016 na Windows Server 2025 — sprawdź macierz wspieranych kombinacji producenta.");
  },
  (s, A) => { const n = s.c.node; if (n && n.i >= famV("node", "18") && ((s.osF === "rhel" && s.osL === "7") || (s.osF === "ubuntu" && s.osL === "18.04"))) A("high", "Node.js", `Oficjalne binaria Node.js ${n.l} wymagają glibc ≥ 2.28 — nie działają na ${FAM[s.osF].name} ${s.osL}.`); },
];
function evalRules(st) { const out = []; RULES.forEach(fn => fn(st, (sev, comp, text) => out.push({ sev, comp, text }))); return out; }
function compatIssues(p, plan, res) {
  const items = [], seen = new Set();
  const push = (sev, comp, text, where) => { const k = comp + "|" + text; if (seen.has(k)) return; seen.add(k); items.push({ sev, comp, text, where }); };
  evalRules(compatState("cur", plan)).forEach(i => push(i.sev, i.comp, i.text, p.scen === "old" ? "stan obecny" : "wybrana konfiguracja"));
  if (p.scen === "old" && plan) {
    evalRules(compatState("tgt", plan)).forEach(i => push(i.sev, i.comp, i.text, "stan docelowy"));
    const seenStep = new Set();
    plan.steps.forEach(st => st.notes.filter(n => n.s !== "info").forEach(n => { const c = comps.find(x => x.id === st.comp); const k = (c ? c.id : "") + n.t; if (seenStep.has(k)) return; seenStep.add(k); push(n.s, c ? c.name : "Całość", n.t, `migracja ${st.from} → ${st.to}`); }));
  } else if (res) {
    res.migNotes.forEach(m => m.items.forEach(b => { const c = comps.find(x => x.id === m.comp); push(b.s, c.name, b.t, `migracja ${m.from} → ${m.to} (${fmtM(m.at)})`); }));
  }
  const rank = { high: 0, med: 1, low: 2 };
  return items.sort((a, b) => rank[a.sev] - rank[b.sev]);
}
const ISS_N = { high: "wysokie", med: "średnie", low: "niskie", info: "info" };
const ISS_C = { high: "var(--critical)", med: "var(--serious)", low: "var(--low)", info: "var(--accent)" };

/* ================= tooltip ================= */
const tip = $("tip");
function showTip(html, e) { tip.innerHTML = html; tip.style.display = "block"; moveTip(e); }
function moveTip(e) { const w = tip.offsetWidth, h = tip.offsetHeight; let x = e.clientX + 14, y = e.clientY + 14; if (x + w > innerWidth - 8) x = e.clientX - w - 14; if (y + h > innerHeight - 8) y = e.clientY - h - 14; tip.style.left = Math.max(8, x) + "px"; tip.style.top = Math.max(8, y) + "px"; }
function hideTip() { tip.style.display = "none"; }
document.addEventListener("mouseover", e => { const el = e.target.closest && e.target.closest("[data-tip]"); if (el) showTip(el.getAttribute("data-tip"), e); });
document.addEventListener("mousemove", e => { if (tip.style.display === "block" && e.target.closest && e.target.closest("[data-tip]")) moveTip(e); });
document.addEventListener("mouseout", e => { const el = e.target.closest && e.target.closest("[data-tip]"); if (el && !el.contains(e.relatedTarget)) hideTip(); });

/* ================= kreator: render ================= */
function verOptions(f, sel, t0, filt) {
  const rec = recIdx(f, t0, filt);
  return FAM[f].v.map((x, i) => { if (filt && !filt(x)) return ""; const s = stOf(D(x.eos), D(x.eol), t0); return `<option value="${esc(x.l)}" ${x.l === sel ? "selected" : ""}>${esc(x.l)} — ${ST_S[s]}${i === rec ? " (zalecana)" : ""}</option>`; }).join("");
}
function stBadge(f, l, t0) { const i = famV(f, l); if (i < 0) return ""; const s = verSt(f, i, t0); const v = FAM[f].v[i]; if (s === "nopatch") return `<span class="st"><i style="background:${ST_C[s]}"></i>bez poprawek bezpieczeństwa · nowe wydania bez aktualizacji w miejscu</span>`; return `<span class="st"><i style="background:${ST_C[s]}"></i>${ST_S[s]} · EOS ${v.eos.slice(0, 7)} · EOL ${v.eol.slice(0, 7)}</span>`; }
function renderWizard() {
  const t0 = startT();
  document.querySelectorAll("#wizard .seg").forEach(g => g.querySelectorAll("button").forEach(b => b.classList.toggle("on", W[g.dataset.w] === b.dataset.v)));
  document.querySelectorAll("#wizard .oldonly").forEach(el => el.style.display = W.scen === "old" ? "" : "none");
  $("lastPatch").value = W.lastPatch;
  $("tpl").innerHTML = `<option value="">— wybierz szablon —</option>` + TPL.map(t => `<option value="${t.k}" ${t.k === W.tpl ? "selected" : ""}>${esc(t.n)}</option>`).join("");
  const buyTxt = W.buy === "no" ? " <b>Płatne wsparcie niewykupione</b> — w okresach płatnych brak poprawek." : "";
  $("scenInfo").innerHTML = (W.scen === "new"
    ? "<b>Nowe wdrożenie:</b> składniki w najnowszych wspieranych seriach z kompletem poprawek (możesz wybrać inną serię). Symulacja pokazuje utrzymanie: aktualizacje, CVE, migracje przed końcem poprawek."
    : W.oldMode === "noupd"
      ? `<b>Stary serwer bez aktualizacji:</b> wybrane stare wersje, ostatnie poprawki ${esc(W.lastPatch)}. Podatności narastają, bo nikt nie instaluje poprawek. Plan modernizacji poniżej jest rekomendacją — przełącz „Z planem modernizacji”, aby go zasymulować.`
      : `<b>Stary serwer z planem modernizacji:</b> stare wersje (ostatnie poprawki ${esc(W.lastPatch)}) → plan: ${W.strat === "inplace" ? "aktualizacje w miejscu krok po kroku" : "budowa nowego serwera i jedno przełączenie"}.`) + buyTxt;
  const curCard = cardOf(W.os.f, W.os.v);
  $("osPicks").innerHTML = OS_CARDS.map(cd => {
    const f = cd.f, filt = cardFilt(cd.k), on = curCard === cd.k, l = on ? W.os.v : FAM[f].v[W.scen === "new" ? recIdx(f, t0, filt) : oldIdx(f, t0, filt)].l;
    return `<label class="pick ${on ? "on" : ""}"><span class="top"><input type="radio" name="os" data-os="${cd.k}" ${on ? "checked" : ""}>${esc(cd.n)}</span>
      <select data-osv="${cd.k}" ${on ? "" : "disabled"}>${verOptions(f, l, t0, filt)}</select>${on ? stBadge(f, l, t0) : '<span class="st muted">kliknij, aby wybrać</span>'}</label>`;
  }).join("");
  $("compPicks").innerHTML = GROUPS.map(([g, fams]) => `<h3>${g}</h3><div class="picks">` + fams.map(f => {
    const allowed = famAllowed(f, W.os.f), on = allowed && W.sel[f] != null;
    const linked = FAM[f].followsOs && allowed ? osLinkedLabel(f, W.os.f, W.os.v) : null;
    const l = linked || (W.sel[f] != null ? W.sel[f] : FAM[f].v[W.scen === "new" ? recIdx(f, t0) : oldIdx(f, t0)].l);
    const sel = linked ? `<select disabled><option>${esc(l)} (${esc(W.os.v)})</option></select>` : `<select data-famv="${f}" ${on ? "" : "disabled"}>${verOptions(f, l, t0)}</select>`;
    const st = !allowed ? '<span class="st">tylko Windows</span>' : linked ? `<span class="st"><i style="background:${ST_C[verSt(W.os.f, famV(W.os.f, W.os.v), t0)]}"></i>wersja i wsparcie jak system (${esc(W.os.v)})</span>` : on ? stBadge(f, l, t0) : '<span class="st muted">nieużywany</span>';
    return `<label class="pick ${on ? "on" : ""} ${allowed ? "" : "dis"}"><span class="top"><input type="checkbox" data-fam="${f}" ${on ? "checked" : ""} ${allowed ? "" : "disabled"}>${esc(FAM[f].name)}</span>
      ${sel}${st}</label>`;
  }).join("") + `</div>`).join("");
}
$("wizard").addEventListener("click", e => {
  const b = e.target.closest(".seg button"); if (!b) return;
  const key = b.parentElement.dataset.w, val = b.dataset.v; if (W[key] === val) return;
  W[key] = val;
  if (key === "scen") { if (val === "new") toLatest(); else toOld(); }
  rebuild();
});
$("wizard").addEventListener("change", e => {
  const t = e.target, t0 = startT();
  if (t.id === "tpl") { if (t.value) applyTemplate(t.value); }
  else if (t.id === "lastPatch") W.lastPatch = t.value || W.lastPatch;
  else if (t.dataset.os) { const cd = OS_CARDS.find(x => x.k === t.dataset.os), filt = cardFilt(cd.k); W.os = { f: cd.f, v: FAM[cd.f].v[W.scen === "new" ? recIdx(cd.f, t0, filt) : oldIdx(cd.f, t0, filt)].l }; }
  else if (t.dataset.osv) W.os.v = t.value;
  else if (t.dataset.fam) { const f = t.dataset.fam; if (t.checked) W.sel[f] = FAM[f].v[W.scen === "new" ? recIdx(f, t0) : oldIdx(f, t0)].l; else delete W.sel[f]; }
  else if (t.dataset.famv) W.sel[t.dataset.famv] = t.value;
  else return;
  rebuild();
});
function rebuild() { buildComps(); renderWizard(); renderEditor(); run(); }

/* ================= edytor zaawansowany ================= */
function renderCatalog() {
  const present = new Set(comps.map(c => c.fam));
  $("catalogSel").innerHTML = GROUPS.flatMap(g => g[1]).filter(f => !present.has(f) && famAllowed(f, W.os.f)).map(f => `<option value="${f}">${esc(FAM[f].name)}</option>`).join("") + `<option value="custom">Własny składnik…</option>`;
}
function renderEditor() {
  const nameOf = id => { const c = comps.find(x => x.id === id); return c ? c.name + " " + c.ver : "?"; };
  let h = `<tr><th>Składnik</th><th>Wersja</th><th>EOS</th><th>EOL</th><th class="num">Cykl akt. (mies.)</th><th class="num">CVE/rok</th><th class="num">Poprawka po (dni)</th>
  <th class="num">h aktual.</th><th class="num">h testy</th><th class="num">h mityg.</th><th class="num">h weryf.</th><th class="num">h migracja</th><th>Zależy od</th><th>Produkt używa bezpośr.</th><th></th></tr>`;
  comps.forEach(c => {
    const opts = comps.filter(o => o.id !== c.id).map(o => `<label><input type="checkbox" data-dep="${o.id}" ${c.deps.includes(o.id) ? "checked" : ""}> ${esc(o.name)} ${esc(o.ver)}</label>`).join("") || '<span class="muted">brak</span>';
    const sumTxt = c.deps.length ? c.deps.map(nameOf).join(", ") : "—";
    const verCell = followsOs(c) ? `<span class="muted">${esc(c.ver)} — jak system</span>` : c.fam === "custom" ? `<input type="text" class="ver" data-f="ver" value="${esc(c.ver)}">` : `<select data-f="vi">${FAM[c.fam].v.map((x, i) => `<option value="${i}" ${i === c.vi ? "selected" : ""}>${esc(x.l)}</option>`).join("")}</select>`;
    const nameCell = c.fam === "custom" ? `<input type="text" data-f="name" value="${esc(c.name)}">` : `${esc(c.name)}<div class="muted" style="font-size:11.5px">${CAT_NAMES[c.cat]}</div>`;
    h += `<tr data-id="${c.id}"><td>${nameCell}</td><td>${verCell}</td>
      <td><input type="date" data-f="eos" value="${c.eos}"></td><td><input type="date" data-f="eol" value="${c.eol}"></td>
      ${["cad", "cve", "lag", "upd", "test", "mit", "verh", "mig"].map(k => `<td class="num"><input type="number" data-f="${k}" min="${k === "cad" ? 1 : 0}" step="${k === "cad" || k === "lag" || k === "mig" ? 1 : 0.5}" value="${c[k]}"></td>`).join("")}
      <td><details class="deps"><summary title="${esc(sumTxt)}">${esc(sumTxt)}</summary><div class="menu">${opts}</div></details></td>
      <td style="text-align:center"><input type="checkbox" data-f="direct" ${c.direct ? "checked" : ""}></td>
      <td>${c.cat === "os" ? "" : `<button data-del title="Usuń">✕</button>`}</td></tr>`;
  });
  $("editTable").innerHTML = h;
  renderCatalog();
}
$("editTable").addEventListener("change", e => {
  const tr = e.target.closest("tr[data-id]"); if (!tr) return;
  const c = comps.find(x => x.id === tr.dataset.id), f = e.target.dataset.f;
  if (e.target.dataset.dep) {
    const d = e.target.dataset.dep;
    if (e.target.checked) { if (createsCycle(c.id, d)) { e.target.checked = false; alert("Ta zależność utworzyłaby cykl."); return; } c.deps.push(d); }
    else c.deps = c.deps.filter(x => x !== d);
    const s = tr.querySelector("summary"), txt = c.deps.map(id => { const o = comps.find(x => x.id === id); return o.name + " " + o.ver; }).join(", ") || "—"; s.textContent = txt; s.title = txt;
  } else if (f === "vi") {
    const i = +e.target.value, v = FAM[c.fam].v[i]; c.vi = i; c.ver = v.l; c.eos = v.eos; c.eol = v.eol;
    if (c.cat === "os") W.os.v = v.l; else W.sel[c.fam] = v.l;
    renderWizard(); renderEditor();
  } else if (f === "direct") c.direct = e.target.checked;
  else if (f) { const num = ["cad", "cve", "lag", "upd", "test", "mit", "verh", "mig"].includes(f); c[f] = num ? Math.max(0, +e.target.value || 0) : e.target.value; if (f === "cad") c.cad = Math.max(1, c.cad); }
  run();
});
$("editTable").addEventListener("click", e => {
  if (!e.target.closest("[data-del]")) return;
  const id = e.target.closest("tr").dataset.id, c = comps.find(x => x.id === id);
  if (c.fam !== "custom") { delete W.sel[c.fam]; rebuild(); return; }
  comps = comps.filter(x => x.id !== id); comps.forEach(x => x.deps = x.deps.filter(d => d !== id));
  renderEditor(); run();
});
document.addEventListener("click", e => { document.querySelectorAll("details.deps[open]").forEach(d => { if (!d.contains(e.target)) d.open = false; }); });
function createsCycle(from, to) { const st = [to], seen = new Set(); while (st.length) { const x = st.pop(); if (x === from) return true; if (seen.has(x)) continue; seen.add(x); const c = comps.find(y => y.id === x); if (c) st.push(...c.deps); } return false; }
$("addBtn").onclick = () => {
  const f = $("catalogSel").value; if (!f) return;
  if (f === "custom") { comps.push({ id: "c" + (uid++), fam: "custom", vi: -1, name: "Własny składnik", ver: "1.0", cat: "lib", eos: "2028-12-31", eol: "2029-12-31", cad: 3, cve: 2, lag: 14, upd: 3, test: 6, mit: 4, verh: 1.5, mig: 60, deps: [W.os.f], direct: true }); renderEditor(); run(); return; }
  const t0 = startT(); W.sel[f] = FAM[f].v[W.scen === "new" ? recIdx(f, t0) : oldIdx(f, t0)].l; rebuild();
};

/* ================= wykresy: pomocnicze ================= */
const svgOpen = (w, h, lab) => `<svg xmlns="http://www.w3.org/2000/svg" class="chart" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${lab}">`;
function niceMax(v) { if (v <= 0) return 1; const e = Math.pow(10, Math.floor(Math.log10(v))); const f = v / e; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * e; }
const width = id => Math.max(280, $(id).clientWidth || 600);
function buckets(res, kind) {
  const step = kind === "q" ? 3 : 1, out = []; let a = res.t0;
  while (a < res.tEnd) { const b = Math.min(addMonths(a, step), res.tEnd), d = new Date(a); out.push({ a, b, label: kind === "q" ? "Q" + (Math.floor(d.getUTCMonth() / 3) + 1) + " " + d.getUTCFullYear() : fmtM(a), h: { ver: 0, mit: 0, upd: 0, test: 0, mig: 0 }, cv: { crit: 0, high: 0, med: 0, low: 0 }, total: 0, cvTotal: 0 }); a = b; }
  const find = t => out.find(x => t >= x.a && t < x.b);
  res.work.forEach(w => { const k = find(w.t); if (k) { k.h[w.type] += w.h; k.total += w.h; } });
  res.cves.forEach(c => { if (c.backlog) return; const k = find(c.t); if (k) { k.cv[c.sev]++; k.cvTotal++; } });
  return out;
}
function yAxis(s, L, R, W, y, maxV, f = nf) { for (let i = 0; i <= 4; i++) { const v = maxV * i / 4; s.push(`<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" stroke="${i ? "var(--grid)" : "var(--axis)"}"/><text x="${L - 6}" y="${y(v) + 4}" font-size="11" text-anchor="end">${f.format(v)}</text>`); } }

/* ================= fazy wsparcia i zagrożenie ================= */
const PH_N = { full: "pełne wsparcie", ext: "rozszerzone — darmowe poprawki bezpieczeństwa", paid: "płatne wsparcie (wykupione) — poprawki dostępne", unpaid: "wymaga płatnego wsparcia — NIEWYKUPIONE, brak poprawek", eol: "po EOL — brak poprawek", nopatch: "edycja bez wsparcia producenta — brak poprawek bezpieczeństwa (zmiana tylko przez instalację nowszego wydania lub innego produktu)" };
function phasesOf(v, buy) {
  if (v.nopatch) return [["nopatch", -Infinity, Infinity]];
  const out = [["full", -Infinity, v.eos]];
  if (v.eol > v.eos) out.push([v.paidExt ? (buy ? "paid" : "unpaid") : "ext", v.eos, v.eol]);
  if (v.esu && v.esu > v.eol) out.push([buy ? "paid" : "unpaid", v.eol, v.esu]);
  out.push(["eol", Math.max(v.eol, v.esu || 0), Infinity]);
  return out;
}
const phaseAt = (v, t, buy) => phasesOf(v, buy).find(([, a, b]) => t >= a && t < b)[0];
const segAt = (res, compId, t) => res.segs.find(g => g.comp === compId && t >= g.start && t < g.end);
// poziom zagrożenia w miesiącu: 2 = niebezpieczny (krytyczna/wysoka podatność po terminie SLA w składniku bez poprawek), 1 = podwyższone ryzyko
function dangerSeries(res, p) {
  const months = []; for (let m = res.t0; m < res.tEnd; m = addMonths(m, 1)) months.push(m);
  let first = null, reason = "", dangerMonths = 0;
  const lv = months.map(m => {
    const mid = Math.min(addMonths(m, 0.5), res.tEnd - 1);
    const unp = {};
    comps.forEach(c => { const g = segAt(res, c.id, mid); if (g && (mid >= g.ver.pe || mid < g.frozenUntil)) unp[c.id] = g; });
    const late = res.cves.filter(v => (v.sev === "crit" || v.sev === "high") && v.t <= mid - (v.sev === "crit" ? p.slaC : p.slaH) * DAY && (v.closedAt == null || v.closedAt > mid));
    const bad = late.filter(v => unp[v.comp] && !(v.mitigatedAt != null && v.mitigatedAt <= mid));
    if (bad.length) {
      dangerMonths++;
      if (first == null) { first = m; const v = bad[0], c = comps.find(x => x.id === v.comp), g = unp[v.comp]; reason = `${v.id} (${SEV_N[v.sev]}) w ${c.name} ${g.label} — ${mid >= g.ver.pe ? (g.ver.nopatch ? "edycja bez poprawek bezpieczeństwa" : phaseAt(g.ver, mid, res.buy) === "unpaid" ? "płatne wsparcie niewykupione" : "wersja po EOL") : "poprawki nie są instalowane"}`; }
      return { l: 2, n: bad.length, u: Object.keys(unp).length };
    }
    return { l: late.length || Object.keys(unp).length ? 1 : 0, n: 0, late: late.length, u: Object.keys(unp).length };
  });
  // okresy, w których produkt jest niebezpieczny: [od, do) — do = pierwszy miesiąc bez zagrożenia albo koniec horyzontu
  const intervals = [];
  lv.forEach((d, i) => {
    if (d.l === 2 && (i === 0 || lv[i - 1].l !== 2)) intervals.push({ from: months[i], to: res.tEnd, open: true });
    if (d.l !== 2 && i > 0 && lv[i - 1].l === 2) { const it = intervals[intervals.length - 1]; it.to = months[i]; it.open = false; }
  });
  return { months, lv, first, reason, dangerMonths, intervals };
}
// „MM.RRRR – MM.RRRR” (ostatni niebezpieczny miesiąc) lub „do końca horyzontu”
const dzRange = it => `${fmtM(it.from)} – ${it.open ? "do końca horyzontu" : fmtM(addMonths(it.to, -1))}`;

/* ================= oś czasu: wiersz na każdą wersję ================= */
function renderTimeline(res, dz) {
  const el = $("timeline"), W_ = Math.max(900, el.parentElement.clientWidth);
  const rows = []; comps.forEach(c => res.segs.filter(g => g.comp === c.id).forEach((g, k) => rows.push({ c, g, k })));
  const L = 200, R = 16, top = 34, rowH = 34, prodH = 44, bandH = dz.intervals.length ? 30 : 0, pt = top + bandH;
  const H = pt + prodH + rows.length * rowH + 10;
  const x = t => L + (Math.min(Math.max(t, res.t0), res.tEnd) - res.t0) / (res.tEnd - res.t0) * (W_ - L - R);
  const s = [svgOpen(W_, H, "Oś czasu wsparcia — wiersz na każdą wersję")];
  s.push(`<defs><pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="6" height="6" fill="var(--critical)" opacity="0.18"/><line x1="0" y1="0" x2="0" y2="6" stroke="var(--critical)" stroke-width="2" opacity="0.7"/></pattern>
    <pattern id="paidp" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(-45)"><rect width="7" height="7" fill="var(--warning)" opacity="0.45"/><line x1="0" y1="0" x2="0" y2="7" stroke="var(--ink-2)" stroke-width="1.6" opacity="0.8"/></pattern></defs>`);
  const d0 = new Date(res.t0);
  for (let q = Date.UTC(d0.getUTCFullYear(), Math.floor(d0.getUTCMonth() / 3) * 3 + 3, 1); q < res.tEnd; q = addMonths(q, 3)) {
    const isY = new Date(q).getUTCMonth() === 0, X = x(q);
    s.push(`<line x1="${X}" x2="${X}" y1="${top - 6}" y2="${H - 6}" stroke="var(--grid)" stroke-width="${isY ? 1 : 0.5}" ${isY ? "" : 'stroke-dasharray="2 3"'}/>`);
    if (isY) s.push(`<text x="${X + 4}" y="${top - 12}" font-size="12" class="ink">${new Date(q).getUTCFullYear()}</text>`);
  }
  if (x(Date.UTC(d0.getUTCFullYear() + 1, 0, 1)) - L > 80) s.push(`<text x="${L + 4}" y="${top - 12}" font-size="11">${fmt(res.t0)}</text>`);
  // wiersz produktu: poziom zagrożenia
  // pas „produkt niebezpieczny” nad wierszem produktu: okresy z datą początku i końca
  if (bandH) {
    s.push(`<text x="8" y="${top + 18}" font-size="12" font-weight="650" fill="var(--critical)">Produkt niebezpieczny</text>`);
    let lastEnd = -Infinity;
    dz.intervals.forEach((it, i) => {
      const a = x(it.from), b = x(it.to), txt = (i === 0 && b - a > 230 ? "niebezpieczny " : "") + dzRange(it);
      const tt = `<b>Produkt niebezpieczny</b><br>${dzRange(it)}${it.open ? "" : "<br>od " + fmtM(it.to) + " ponownie bez niezałatanych krytycznych/wysokich podatności po terminie SLA"}`;
      s.push(`<g data-tip="${attr(tt)}"><rect x="${a}" y="${top + 4}" width="${Math.max(2, b - a)}" height="${bandH - 6}" fill="transparent"/>
        <line x1="${a}" x2="${Math.max(a + 2, b - 1)}" y1="${top + 21}" y2="${top + 21}" stroke="var(--critical)" stroke-width="3"/>
        <line x1="${a}" x2="${a}" y1="${top + 16}" y2="${top + 26}" stroke="var(--critical)" stroke-width="2"/>${it.open ? "" : `<line x1="${b - 1}" x2="${b - 1}" y1="${top + 16}" y2="${top + 26}" stroke="var(--critical)" stroke-width="2"/>`}</g>`);
      // etykieta nad kreską, jeśli mieści się bez nachodzenia na poprzednią
      const w = txt.length * 6.4, lx = Math.min(Math.max(a, lastEnd + 8), W_ - R - w);
      if (lx >= lastEnd + 6 && lx >= L) { s.push(`<text x="${lx}" y="${top + 12}" font-size="11.5" font-weight="650" fill="var(--critical)" pointer-events="none">${txt}</text>`); lastEnd = lx + w; }
    });
  }
  s.push(`<text x="8" y="${pt + 17}" font-size="12.5" class="ink" font-weight="650">Produkt</text><text x="8" y="${pt + 31}" font-size="11">bezpieczeństwo</text>`);
  const LV = [["var(--good)", 0.4, "bezpieczny — poprawki dostępne i instalowane"], ["var(--warning)", 0.6, "podwyższone ryzyko"], ["var(--critical)", 0.9, "NIEBEZPIECZNY — krytyczne/wysokie podatności bez możliwości załatania"]];
  dz.months.forEach((m, i) => {
    const me = Math.min(addMonths(m, 1), res.tEnd), d = dz.lv[i], [col, op, n] = LV[d.l];
    const tt = `<b>${fmtM(m)} — ${n}</b>` + (d.l === 2 ? `<br>Otwarte krytyczne/wysokie po terminie SLA w składnikach bez poprawek: ${d.n}` : d.l === 1 ? `<br>${d.late ? "Poprawki spóźnione względem SLA: " + d.late + "<br>" : ""}Składniki bez poprawek: ${d.u}` : "");
    s.push(`<rect x="${x(m)}" y="${pt + 8}" width="${Math.max(1, x(me) - x(m) - 1)}" height="22" fill="${col}" opacity="${op}" data-tip="${attr(tt)}"/>`);
  });
  // pionowe linie początku i końca okresów zagrożenia
  dz.intervals.forEach(it => {
    s.push(`<line x1="${x(it.from)}" x2="${x(it.from)}" y1="${top + 26}" y2="${H - 6}" stroke="var(--critical)" stroke-width="1.5" stroke-dasharray="6 4" opacity="0.8" pointer-events="none"/>`);
    if (!it.open) s.push(`<line x1="${x(it.to)}" x2="${x(it.to)}" y1="${top + 26}" y2="${H - 6}" stroke="var(--critical)" stroke-width="1.5" stroke-dasharray="2 4" opacity="0.6" pointer-events="none"/>`);
  });
  let y = pt + prodH;
  rows.forEach(({ c, g, k }) => {
    const cy = y + rowH / 2;
    s.push(`<line x1="0" x2="${W_}" y1="${y}" y2="${y}" stroke="${k ? "var(--grid)" : "var(--axis)"}" stroke-width="${k ? 0.5 : 1}"/>`);
    if (k === 0) s.push(`<text x="8" y="${y + 14}" font-size="12.5" class="ink" font-weight="600">${esc(trunc(c.name, 25))}</text><text x="8" y="${y + 28}" font-size="11">wersja ${esc(trunc(g.label, 20))}</text>`);
    else s.push(`<text x="20" y="${y + 21}" font-size="12" class="ink">↳ ${g.fam !== c.fam ? "" : "wersja "}${esc(trunc(g.label, 24))}</text>`);
    const v = g.ver;
    // cały cykl życia wersji (wyblakły) + okres użytkowania (pełny kolor)
    phasesOf(v, res.buy).forEach(([ph, a, b]) => {
      if (b <= res.t0 || a >= res.tEnd) return;
      const fill = ph === "eol" || ph === "unpaid" || ph === "nopatch" ? "url(#hatch)" : ph === "paid" ? "url(#paidp)" : ph === "full" ? "var(--good)" : "var(--warning)";
      const baseOp = ph === "full" || ph === "ext" ? 0.42 : 1;
      const tt = `<b>${esc(c.name)} ${esc(g.label)}</b><br>${PH_N[ph]}${ph === "paid" || ph === "unpaid" ? "<br>Program: " + esc(a >= v.eol ? v.esuName || "wsparcie płatne" : v.paidExt) : ""}<br>${a > res.t0 ? fmt(a) : "…"} → ${b < res.tEnd ? fmt(b) : "…"}<br><span class='muted'>EOS ${fmt(v.eos)} · EOL ${fmt(v.eol)}${v.esu ? " · płatne do " + fmt(v.esu) : ""}${v.fc ? " (prognoza)" : ""}</span>`;
      s.push(`<rect x="${x(a)}" y="${cy - 6}" width="${Math.max(1, x(b) - x(a) - 1)}" height="12" rx="3" fill="${fill}" opacity="${baseOp * 0.25}" data-tip="${attr(tt)}"/>`);
      const ua = Math.max(a, g.start), ub = Math.min(b, g.end);
      if (ub > ua) {
        s.push(`<rect x="${x(ua)}" y="${cy - 7}" width="${Math.max(1, x(ub) - x(ua) - 1)}" height="14" rx="3" fill="${fill}" opacity="${baseOp}" data-tip="${attr(tt + "<br><b>W użyciu</b> " + fmt(ua) + " → " + fmt(ub))}"/>`);
        if ((ph === "paid" || ph === "unpaid" || ph === "nopatch") && x(ub) - x(ua) > 70) s.push(`<text x="${x(ua) + 4}" y="${cy + 4}" font-size="10.5" class="ink" pointer-events="none">${ph === "paid" ? "płatne" : ph === "nopatch" ? "bez poprawek" : "niewykupione"}</text>`);
      }
    });
    if (g.frozenUntil > g.start) {
      const bb = Math.min(g.frozenUntil, g.end);
      s.push(`<rect x="${x(g.start)}" y="${cy - 10}" width="${Math.max(2, x(bb) - x(g.start) - 1)}" height="20" rx="4" fill="none" stroke="var(--ink-2)" stroke-width="1.2" stroke-dasharray="3 3" data-tip="${attr(`<b>Brak aktualizacji</b><br>${esc(c.name)} ${esc(g.label)}<br>${fmt(g.start)} → ${bb >= res.tEnd ? "koniec horyzontu" : fmt(bb)}`)}"/>`);
    }
    // migracja na tę wersję: przygotowanie + go-live
    if (k > 0) res.migs.filter(m => m.comp === c.id && m.end === g.start).forEach(m => {
      const tt = `<b>${m.planned ? "Plan modernizacji" : "Migracja"}: ${esc(c.name)}</b><br>${esc(m.from)} → ${esc(m.to)}<br>przygotowanie ${fmt(m.start)} → go‑live ${fmt(m.end)}`;
      s.push(`<rect x="${x(m.start)}" y="${cy - 11}" width="${Math.max(3, x(m.end) - x(m.start))}" height="22" rx="4" fill="var(--s5)" opacity="0.2" stroke="var(--s5)" stroke-dasharray="3 2" data-tip="${attr(tt)}"/>`);
      s.push(`<path d="M${x(m.end)} ${cy - 8} l6 8 l-6 8 l-6 -8z" fill="var(--s5)" stroke="var(--surface)" stroke-width="1.5" data-tip="${attr(tt)}"/>`);
    });
    const inSeg = t => t >= g.start && t < g.end;
    res.updates.filter(u => u.comp === c.id && inSeg(u.t)).forEach(u => {
      const X = x(u.t), em = u.kind === "emerg", cu = u.kind === "catchup";
      const n = (em ? "Aktualizacja awaryjna" : cu ? "Doinstalowanie zaległych poprawek" : u.kind === "sec" ? "Aktualizacja bezpieczeństwa" : "Aktualizacja planowa") + (u.paid ? " — PŁATNA" : "");
      const col = u.paid ? "var(--s2)" : em ? "var(--s3)" : cu ? "var(--s1)" : "var(--muted)";
      s.push(`<line x1="${X}" x2="${X}" y1="${em || cu || u.paid ? cy - 15 : cy - 12}" y2="${cy - 7}" stroke="${col}" stroke-width="${em || cu || u.paid ? 2.5 : 1.5}"/>`);
      if (u.paid) s.push(`<circle cx="${X}" cy="${cy - 15}" r="2.2" fill="${col}"/>`);
      s.push(`<rect x="${X - 3}" y="${cy - 17}" width="6" height="11" fill="transparent" data-tip="${attr(`<b>${n}</b><br>${esc(c.name)} ${esc(u.ver)}<br>${fmt(u.t)}${u.paid ? "<br>wymaga: " + esc(v.paidAll && u.t < v.eos ? v.paidAll : u.t >= v.eol ? v.esuName || "płatne wsparcie" : v.paidExt || v.paidAll || "") : ""}`)}"/>`);
    });
    res.cves.filter(v2 => v2.comp === c.id && !v2.backlog && inSeg(v2.t)).forEach(v2 => {
      const r = { crit: 5, high: 4.2, med: 3.3, low: 2.8 }[v2.sev], col = SEV_C[v2.sev], open = v2.closedAt == null || v2.closedAt >= res.tEnd;
      const mtxt = v2.mitigatedAt != null ? "zmitygowana od " + fmt(v2.mitigatedAt) : v2.mitigFail ? "mitygacja nieskuteczna lub niemożliwa" : null;
      const status = !v2.supported ? ["brak poprawki (EOL lub niewykupione wsparcie)", mtxt].filter(Boolean).join("; ") : [mtxt, v2.emergency ? "aktualizacja awaryjna " + fmt(v2.patchAt) : null, v2.bundled && v2.closedAt ? "w aktualizacji " + fmt(v2.closedAt) : null].filter(Boolean).join("; ");
      const tt = `<b>${esc(v2.id)}${v2.wave ? " — fala 0‑day" : ""}</b><br>${esc(c.name)} ${esc(v2.ver)}<br>Ważność: ${SEV_N[v2.sev]} · ${fmt(v2.t)}<br>${status}<br>${open ? "<b>Niezałatana do końca horyzontu</b>" : "Zamknięta: " + fmt(v2.closedAt)}`;
      const yy = cy + 10;
      s.push(v2.wave ? `<path d="M${x(v2.t)} ${yy - 6} l6 11 h-12z" fill="${open ? "var(--surface)" : col}" stroke="${open ? col : "var(--surface)"}" stroke-width="${open ? 2 : 1.5}" data-tip="${attr(tt)}"/>`
        : `<circle cx="${x(v2.t)}" cy="${yy}" r="${r}" fill="${open ? "var(--surface)" : col}" stroke="${open ? col : "var(--surface)"}" stroke-width="2" data-tip="${attr(tt)}"/>`);
    });
    y += rowH;
  });
  const today = Date.now();
  if (today > res.t0 && today < res.tEnd) s.push(`<line x1="${x(today)}" x2="${x(today)}" y1="${top - 6}" y2="${H}" stroke="var(--accent)" stroke-width="1.5"/>`);
  s.push(`<line x1="${L}" x2="${L}" y1="${top - 6}" y2="${H}" stroke="var(--axis)"/></svg>`);
  el.innerHTML = s.join("");
  $("tlLegend").innerHTML = [
    `<span><i class="sw" style="background:var(--good);opacity:.5"></i>Pełne wsparcie</span>`, `<span><i class="sw" style="background:var(--warning);opacity:.6"></i>Rozszerzone — darmowe poprawki</span>`,
    `<span><i class="sw" style="background:repeating-linear-gradient(-45deg,var(--ink-2) 0 2px,var(--warning) 2px 6px)"></i>Płatne wsparcie (wykupione)</span>`, `<span><i class="sw hatch"></i>Brak poprawek (EOL / niewykupione / edycja bez wsparcia)</span>`,
    `<span><i class="sw frz"></i>Brak aktualizacji</span>`, `<span>wyblakłe — cykl życia wersji poza okresem użycia</span>`,
    `<span><i class="sw line" style="background:var(--muted);width:2px;height:10px"></i>Aktualizacja</span>`, `<span><i class="sw dot" style="background:var(--s2);width:8px;height:8px"></i>Aktualizacja płatna</span>`,
    `<span><i class="sw line" style="background:var(--s3);width:3px;height:12px"></i>awaryjna</span>`, `<span><i class="sw line" style="background:var(--s1);width:3px;height:12px"></i>zaległe poprawki</span>`,
    `<span><i class="sw" style="background:var(--s5);transform:rotate(45deg);width:9px;height:9px"></i>Migracja (go‑live)</span>`,
    `<span><i class="sw dot" style="background:var(--critical)"></i>podatność krytyczna</span>`, `<span><i class="sw dot" style="background:var(--serious)"></i>wysoka</span>`,
    `<span><i class="sw dot" style="background:var(--warning)"></i>średnia</span>`, `<span><i class="sw dot" style="background:var(--low)"></i>niska</span>`,
    `<span><i class="sw ring"></i>niezałatana do końca</span>`, `<span>▲ fala 0‑day</span>`, `<span><i class="sw line" style="background:var(--critical);height:3px"></i>okres, w którym produkt jest niebezpieczny (od – do)</span>`].join("");
}

/* ================= zakupy, licencje, płatne wsparcie ================= */
function purchases(res, p, plan) {
  const buys = [], paid = [];
  const nm = id => comps.find(c => c.id === id);
  if (p.scen === "new") comps.forEach(c => { const F = FAM[c.fam]; if (F && F.lic !== "free" && !altFor(c)) buys.push({ t: res.t0, c, change: "wdrożenie " + c.ver, need: F.lic === "perp" ? "buy" : "contract", note: (F.lic === "perp" ? "Zakup licencji. " : F.lic === "sub" ? "Zakup subskrypcji. " : "Zakup licencji i rocznego wsparcia. ") + (F.licNote || "") }); });
  if (plan && p.mode === "plan" && p.strat === "newsrv" && plan.steps[0]) buys.push({ t: plan.steps[0].start, c: comps.find(c => c.cat === "os"), change: "nowy serwer", need: "buy", note: "Sprzęt lub maszyna wirtualna oraz licencja/subskrypcja systemu dla nowego serwera." });
  res.migs.forEach(m => {
    const c = nm(m.comp);
    if (m.alt) {
      const g0 = res.segs.find(g => g.comp === m.comp && g.end === m.end), F0 = FAM[g0 ? g0.fam : c.fam];
      buys.push({ t: m.end, c, change: `${m.from} → ${m.to}`, need: "save", note: "Darmowy odpowiednik. " + (F0 && F0.lic !== "free" ? "Koniec opłat: " + (F0.licNote || LIC_N[F0.lic]) : F0 && (F0.paidExt || F0.paidAll) ? "Bez potrzeby płatnego wsparcia: " + (F0.paidExt || F0.paidAll) + "." : "Bez opłat licencyjnych.") });
      return;
    }
    const F = FAM[m.toFam || c.fam]; if (!F || F.lic === "free") return;
    if (F.licOf) { const g0 = res.segs.find(g => g.comp === m.comp && g.end === m.end), g1 = res.segs.find(g => g.comp === m.comp && g.start === m.end); if (g0 && g1) { const [need, note] = F.licOf(g0.ver, g1.ver); if (need === "free") return; buys.push({ t: m.end, c, change: `${m.from} → ${m.to}`, need, note: note + " " + (F.licNote || "") }); return; } }
    buys.push({ t: m.end, c, change: `${m.from} → ${m.to}`, need: F.lic === "perp" ? "buy" : "contract", note: LIC_N[F.lic] + ". " + (F.licNote || "") });
  });
  res.segs.forEach(g => {
    const c = nm(g.comp), v = g.ver, wins = [];
    if (v.paidAll) wins.push([v.paidAll, g.start, g.end, "subskrypcja (cały okres użycia)"]);
    if (v.paidExt && v.eol > v.eos) wins.push([v.paidExt, v.eos, v.eol, "wsparcie rozszerzone"]);
    if (v.esu && v.esu > v.eol) wins.push([v.esuName || "wsparcie płatne", v.eol, v.esu, "wsparcie po EOL"]);
    wins.forEach(([prog, a, b, kind]) => {
      const ua = Math.max(a, g.start, res.t0), ub = Math.min(b, g.end, res.tEnd); if (ub <= ua) return;
      const cv = res.cves.filter(x => x.comp === g.comp && x.t >= ua && x.t < ub && !x.backlog);
      paid.push({ c, ver: g.label, prog, kind, a: ua, b: ub, sub: kind.startsWith("subskrypcja"), crit: cv.filter(x => x.sev === "crit" || x.sev === "high").length, all: cv.length });
    });
  });
  buys.sort((a, b) => a.t - b.t); paid.sort((a, b) => a.a - b.a);
  return { buys, paid };
}
function renderPurchases(res, p, plan, dz, dzAlt) {
  const { buys, paid } = purchases(res, p, plan);
  const dTxt = d => d.first != null ? `<b style="color:var(--critical)">${dzRange(d.intervals[0])}</b>${d.intervals.length > 1 ? ` (oraz ${d.intervals.slice(1).map(dzRange).join(", ")})` : ""} — ${esc(d.reason)}; łącznie ${d.dangerMonths} mies. w horyzoncie` : `<b style="color:var(--good)">nie w horyzoncie symulacji</b>`;
  $("dangerBox").innerHTML = `<div><b>Bieżący scenariusz${res.buy ? " (płatne wsparcie wykupione)" : " (płatne wsparcie niewykupione)"}:</b> produkt niebezpieczny ${dTxt(dz)}</div>` +
    (res.buy ? `<div style="margin-top:4px"><b>Bez płatnego wsparcia, z migracjami:</b> ${dTxt(dzAlt.noBuy)}</div>` : "") +
    `<div style="margin-top:4px"><b>Bez płatnego wsparcia i bez zakupu nowych wersji</b> (tylko darmowe poprawki, bez migracji): ${dTxt(dzAlt.none)}</div>
    <div class="muted" style="margin-top:6px;font-size:12px">„Niebezpieczny” = istnieje krytyczna lub wysoka podatność otwarta dłużej niż SLA w składniku, dla którego nie można zainstalować poprawki (EOL, niewykupione wsparcie albo serwer bez aktualizacji).</div>`;
  $("buyTable").innerHTML = `<tr><th>Data</th><th>Składnik</th><th>Zmiana</th><th>Zakup</th><th>Uwagi</th></tr>` + (buys.map(b => `<tr><td>${fmtM(b.t)}</td><td>${esc(b.c.name)}</td><td>${esc(b.change)}</td><td>${b.need === "buy" ? `<span class="badge"><i style="background:var(--critical)"></i>nowa licencja / produkt</span>` : b.need === "save" ? `<span class="badge"><i style="background:var(--good)"></i>bez zakupu — darmowy odpowiednik</span>` : `<span class="badge"><i style="background:var(--warning)"></i>w ramach aktywnej umowy</span>`}</td><td class="wrapc">${esc(b.note)}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">Brak zmian wymagających zakupu — składniki są bezpłatne.</td></tr>`);
  $("paidTable").innerHTML = `<tr><th>Składnik i wersja</th><th>Program wsparcia</th><th>Okres</th><th>Status w symulacji</th><th class="num">Podatności kryt./wys. w okresie</th></tr>` + (paid.map(r => `<tr><td>${esc(r.c.name)} ${esc(r.ver)}</td><td>${esc(r.prog)}<div class="muted" style="font-size:11.5px">${esc(r.kind)}</div></td><td>${fmtM(r.a)} – ${fmtM(r.b)}</td><td>${r.sub ? `<span class="badge"><i style="background:var(--warning)"></i>wymagana subskrypcja</span>` : res.buy ? `<span class="badge"><i style="background:var(--good)"></i>wykupione — poprawki dostępne</span>` : `<span class="badge"><i style="background:var(--critical)"></i>niewykupione — brak poprawek</span>`}</td><td class="num">${r.crit} <span class="muted">/ ${r.all}</span></td></tr>`).join("") || `<tr><td colspan="5" class="muted">W horyzoncie żaden używany składnik nie wymaga płatnego wsparcia.</td></tr>`);
}

/* ================= ekspozycja (otwarte podatności) ================= */
function openSeries(res) {
  const months = []; for (let m = res.t0; m <= res.tEnd + DAY; m = addMonths(m, 1)) months.push(Math.min(m, res.tEnd));
  const all = months.map(m => res.cves.filter(v => v.t <= m && (v.closedAt == null || v.closedAt > m)));
  return { months, total: all.map(a => a.length), ch: all.map((a, i) => a.filter(v => (v.sev === "crit" || v.sev === "high") && !(v.mitigatedAt != null && v.mitigatedAt <= months[i])).length) };
}
function renderLines(id, legendId, t0, tEnd, series, unit, fmtv = nf) {
  const W_ = width(id), H = 260, L = 52, R = 90, top = 14, bot = 36;
  const months = series[0].months;
  const maxV = niceMax(Math.max(...series.flatMap(s => s.pts), 1));
  const x = t => L + (t - t0) / (tEnd - t0) * (W_ - L - R), y = v => top + (1 - v / maxV) * (H - top - bot);
  const s = [svgOpen(W_, H, "Wykres liniowy")]; yAxis(s, L, R, W_, y, maxV, fmtv);
  const d0 = new Date(t0);
  for (let yv = d0.getUTCFullYear() + 1; Date.UTC(yv, 0, 1) < tEnd; yv++) { const X = x(Date.UTC(yv, 0, 1)); s.push(`<text x="${X}" y="${H - bot + 16}" font-size="11" text-anchor="middle">${yv}</text><line x1="${X}" x2="${X}" y1="${H - bot}" y2="${H - bot + 4}" stroke="var(--axis)"/>`); }
  const lastY = [];
  series.forEach(se => {
    s.push(`<polyline fill="none" stroke="${se.col}" stroke-width="2" ${se.dash ? 'stroke-dasharray="5 4"' : ""} points="${se.pts.map((v, i) => `${x(months[i])},${y(v)}`).join(" ")}"/>`);
    let ly = y(se.pts[se.pts.length - 1]) + 4; lastY.forEach(o => { if (Math.abs(o - ly) < 13) ly = o + 13; }); lastY.push(ly);
    s.push(`<text x="${W_ - R + 6}" y="${ly}" font-size="11" class="ink">${fmtv.format(se.pts[se.pts.length - 1])}${unit}</text>`);
  });
  s.push(`<g class="hov" pointer-events="none" style="display:none"><line class="hl" y1="${top}" y2="${H - bot}" stroke="var(--axis)"/>${series.map((se, i) => `<circle class="hd${i}" r="4.5" fill="${se.col}" stroke="var(--surface)" stroke-width="2"/>`).join("")}</g>`);
  s.push(`<rect class="ov" x="${L}" y="${top}" width="${W_ - L - R}" height="${H - top - bot}" fill="transparent"/></svg>`);
  $(id).innerHTML = s.join("");
  const root = $(id), ov = root.querySelector(".ov"), g = root.querySelector(".hov");
  ov.addEventListener("mousemove", e => {
    const rect = ov.ownerSVGElement.getBoundingClientRect(), px = (e.clientX - rect.left) * (W_ / rect.width);
    const t = t0 + (px - L) / (W_ - L - R) * (tEnd - t0); let i = 0, best = Infinity; months.forEach((m, k) => { const d = Math.abs(m - t); if (d < best) { best = d; i = k; } });
    g.style.display = ""; const hl = root.querySelector(".hl"); hl.setAttribute("x1", x(months[i])); hl.setAttribute("x2", x(months[i]));
    series.forEach((se, k) => { const c = root.querySelector(".hd" + k); c.setAttribute("cx", x(months[i])); c.setAttribute("cy", y(se.pts[i])); });
    showTip(`<b>${fmtM(months[i])}</b>` + series.map(se => `<div class="tr"><span><i class="sw line" style="background:${se.col}"></i> ${esc(se.name)}</span><span>${fmtv.format(se.pts[i])}${unit}</span></div>`).join(""), e);
  });
  ov.addEventListener("mouseleave", () => { g.style.display = "none"; hideTip(); });
  $(legendId).innerHTML = series.map(se => `<span><i class="sw line" style="background:${se.col}"></i>${esc(se.name)}</span>`).join("");
}
function renderExposure(res, alt, altName, p) {
  const a = openSeries(res), b = openSeries(alt);
  const cur = p.mode === "new" ? "Nowe wdrożenie z aktualizacjami" : p.mode === "noupd" ? "Bez aktualizacji" : "Z planem modernizacji";
  renderLines("exposure", "expLegend", res.t0, res.tEnd, [
    { name: cur + " — wszystkie", col: "var(--s1)", pts: a.total, months: a.months },
    { name: cur + " — krytyczne i wysokie bez skutecznej mitygacji", col: "var(--s1)", dash: true, pts: a.ch, months: a.months },
    { name: altName + " — wszystkie", col: "var(--s2)", pts: b.total, months: b.months },
  ], "");
  $("expHint").textContent = p.scen === "old" ? "Liczba otwartych podatności (łącznie z zaległymi od daty ostatnich poprawek) — scenariusz bieżący i alternatywny." : "Liczba otwartych podatności w czasie oraz dla porównania: co by było, gdyby nie instalować poprawek.";
}

/* ================= pracochłonność, CVE, porównanie ================= */
function renderEffort(res, p, bk) {
  const W_ = width("effort"), H = 300, L = 48, R = 12, top = 16, bot = 40, months = bucketKind === "q" ? 3 : 1;
  const cap = p.fte * 140 * months, maxV = niceMax(Math.max(cap * 1.05, ...bk.map(b => b.total)));
  const y = v => top + (1 - v / maxV) * (H - top - bot), bw = (W_ - L - R) / bk.length, barW = Math.max(3, Math.min(42, bw * 0.7));
  const s = [svgOpen(W_, H, "Pracochłonność w okresach")]; yAxis(s, L, R, W_, y, maxV); s.push(`<text x="4" y="${top - 4}" font-size="11">h</text>`);
  const every = Math.ceil(bk.length / Math.max(1, Math.floor((W_ - L) / 64)));
  bk.forEach((b, i) => {
    const cx = L + bw * i + bw / 2; let acc = 0;
    TYPES.forEach(([k, , col]) => { const v = b.h[k]; if (v <= 0) return; const y1 = y(acc + v), y0 = y(acc); acc += v; const hh = Math.max(0, y0 - y1 - 2); if (hh > 0) s.push(`<rect x="${cx - barW / 2}" y="${y1}" width="${barW}" height="${hh}" rx="${hh > 6 ? 2 : 0}" fill="var(${col})"/>`); });
    if (b.total > cap) s.push(`<text x="${cx}" y="${y(b.total) - 4}" font-size="11" text-anchor="middle" fill="var(--critical)">▲</text>`);
    const tt = `<b>${b.label}</b>` + TYPES.map(([k, n, col]) => `<div class="tr"><span><i class="sw" style="background:var(${col})"></i> ${n}</span><span>${nf1.format(b.h[k])} h</span></div>`).join("") +
      `<div class="tr"><b>Razem</b><b>${nf1.format(b.total)} h</b></div><div class="tr"><span>Pojemność zespołu</span><span>${nf.format(cap)} h</span></div><div class="tr"><span>Wymagane FTE</span><span>${nf1.format(b.total / (140 * months))}</span></div>`;
    s.push(`<rect x="${L + bw * i}" y="${top}" width="${bw}" height="${H - top - bot}" fill="transparent" data-tip="${attr(tt)}"/>`);
    if (i % every === 0) s.push(`<text x="${cx}" y="${H - bot + 16}" font-size="11" text-anchor="middle">${b.label}</text>`);
  });
  s.push(`<line x1="${L}" x2="${W_ - R}" y1="${y(cap)}" y2="${y(cap)}" stroke="var(--ink-2)" stroke-width="1.5" stroke-dasharray="5 4" pointer-events="none"/><text x="${W_ - R}" y="${y(cap) - 5}" font-size="11" text-anchor="end" class="ink">Pojemność zespołu: ${nf.format(cap)} h</text></svg>`);
  $("effort").innerHTML = s.join("");
  $("effLegend").innerHTML = TYPES.map(([, n, col]) => `<span><i class="sw" style="background:var(${col})"></i>${n}</span>`).join("") + `<span><i class="sw line" style="background:var(--ink-2)"></i>Pojemność</span><span><span style="color:var(--critical)">▲</span> przekroczenie pojemności</span>`;
}
function renderCves(res, bk) {
  const W_ = width("cves"), H = 260, L = 36, R = 10, top = 14, bot = 36;
  const exp = bk.map(b => res.baseRate * (b.b - b.a) / YEAR), maxV = niceMax(Math.max(...bk.map(b => b.cvTotal), ...exp, 1));
  const y = v => top + (1 - v / maxV) * (H - top - bot), bw = (W_ - L - R) / bk.length, barW = Math.max(2, Math.min(30, bw * 0.7));
  const SC = ["crit", "high", "med", "low"];
  const s = [svgOpen(W_, H, "Liczba CVE w okresach")]; yAxis(s, L, R, W_, y, maxV, nf1);
  const every = Math.ceil(bk.length / Math.max(1, Math.floor((W_ - L) / 64)));
  bk.forEach((b, i) => {
    const cx = L + bw * i + bw / 2; let acc = 0;
    SC.forEach(k => { const v = b.cv[k]; if (!v) return; const y1 = y(acc + v), y0 = y(acc); acc += v; const hh = Math.max(0, y0 - y1 - 2); if (hh > 0) s.push(`<rect x="${cx - barW / 2}" y="${y1}" width="${barW}" height="${hh}" fill="${SEV_C[k]}"/>`); });
    const tt = `<b>${b.label}</b>` + SC.map(k => `<div class="tr"><span><i class="sw dot" style="background:${SEV_C[k]}"></i> ${SEV_N[k]}</span><span>${b.cv[k]}</span></div>`).join("") + `<div class="tr"><b>Razem</b><b>${b.cvTotal}</b></div><div class="tr"><span>Oczekiwane (trend stały)</span><span>${nf1.format(exp[i])}</span></div>`;
    s.push(`<rect x="${L + bw * i}" y="${top}" width="${bw}" height="${H - top - bot}" fill="transparent" data-tip="${attr(tt)}"/>`);
    if (i % every === 0) s.push(`<text x="${cx}" y="${H - bot + 16}" font-size="11" text-anchor="middle">${b.label}</text>`);
  });
  s.push(`<polyline fill="none" stroke="var(--ink-2)" stroke-width="2" stroke-dasharray="5 4" pointer-events="none" points="${bk.map((b, i) => `${L + bw * i + bw / 2},${y(exp[i])}`).join(" ")}"/></svg>`);
  $("cves").innerHTML = s.join("");
  $("cveLegend").innerHTML = SC.map(k => `<span><i class="sw" style="background:${SEV_C[k]}"></i>${SEV_N[k]}</span>`).join("") + `<span><i class="sw line" style="background:var(--ink-2)"></i>oczekiwane przy trendzie stałym</span>`;
}
function cumSeries(res) { const months = []; for (let m = res.t0; m <= res.tEnd + DAY; m = addMonths(m, 1)) months.push(Math.min(m, res.tEnd)); let acc = 0, wi = 0; const w = res.work; return { months, pts: months.map(m => { while (wi < w.length && w[wi].t <= m) acc += w[wi++].h; return acc; }) }; }
function renderCompare(resConst, alt, altName) {
  const a = cumSeries(resConst), b = cumSeries(alt);
  renderLines("cmp", "cmpLegend", resConst.t0, resConst.tEnd, [{ name: "Trend stały", col: "var(--s1)", ...a }, { name: altName, col: "var(--s2)", ...b }], " h");
}

/* ================= graf zależności ================= */
function renderGraph(res) {
  const W_ = width("graph"), depth = {};
  const calc = (id, st = new Set()) => { if (depth[id] != null) return depth[id]; if (st.has(id)) return 0; st.add(id); const c = comps.find(x => x.id === id); const d = c.deps.filter(dd => comps.some(x => x.id === dd)).length ? 1 + Math.max(...c.deps.filter(dd => comps.some(x => x.id === dd)).map(dd => calc(dd, st))) : 0; depth[id] = d; return d; };
  comps.forEach(c => calc(c.id));
  const maxD = comps.length ? Math.max(...Object.values(depth)) : 0, layers = [];
  for (let i = 0; i <= maxD; i++) layers.push(comps.filter(c => depth[c.id] === i));
  const nodeH = 40, gapY = 34, maxN = Math.max(1, ...layers.map(l => l.length));
  const nodeW = Math.min(150, Math.max(70, (W_ - 10) / maxN - 8)), H = (maxD + 2) * (nodeH + gapY) + 10, pos = {};
  layers.forEach((l, li) => { const yy = H - 10 - (li + 1) * (nodeH + gapY) + gapY, step = (W_ - 10) / l.length; l.forEach((c, k) => pos[c.id] = { x: 5 + step * k + step / 2, y: yy }); });
  pos.__prod = { x: W_ / 2, y: 10 };
  const s = [svgOpen(W_, H, "Graf zależności"), `<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="var(--muted)"/></marker></defs>`];
  const edge = (a, b) => { const A = pos[a], B = pos[b]; if (A && B) s.push(`<line x1="${A.x}" y1="${A.y + nodeH}" x2="${B.x}" y2="${B.y}" stroke="var(--muted)" stroke-width="1.2" marker-end="url(#arr)" opacity="0.8"/>`); };
  comps.forEach(c => c.deps.forEach(d => edge(c.id, d)));
  comps.filter(c => c.direct).forEach(c => edge("__prod", c.id));
  const node = (id, title, sub, col, tt) => { const p0 = pos[id]; s.push(`<g data-tip="${attr(tt)}"><rect x="${p0.x - nodeW / 2}" y="${p0.y}" width="${nodeW}" height="${nodeH}" rx="8" fill="var(--surface-2)" stroke="${col}" stroke-width="2"/><text x="${p0.x}" y="${p0.y + 17}" text-anchor="middle" font-size="12" class="ink">${esc(trunc(title, Math.floor(nodeW / 7)))}</text><text x="${p0.x}" y="${p0.y + 31}" text-anchor="middle" font-size="11">${esc(trunc(sub, Math.floor(nodeW / 6.3)))}</text></g>`); };
  node("__prod", "Fikcyjny produkt", "zależności: " + comps.filter(c => c.direct).length, "var(--accent)", "<b>Fikcyjny produkt</b><br>Bezpośrednio używa: " + comps.filter(c => c.direct).map(c => esc(c.name)).join(", "));
  comps.forEach(c => { const st = compSt(c, res.t0); node(c.id, c.name, c.ver + " · " + ST_S[st], ST_C[st], `<b>${esc(c.name)} ${esc(c.ver)}</b><br>Status na start: ${ST_N[st]}<br>Zależnych (z produktem): ${res.deps[c.id]}<br>Zależy od: ${c.deps.map(d => { const o = comps.find(x => x.id === d); return o ? esc(o.name) : ""; }).join(", ") || "—"}`); });
  s.push("</svg>"); $("graph").innerHTML = s.join("");
}

/* ================= KPI, plan, tabele ================= */
function renderKpis(res, p, bk, plan, issues, dz, dzAlt) {
  const tot = res.work.reduce((s, w) => s + w.h, 0), months = p.horizon * 12;
  const nw = res.cves.filter(c => !c.backlog), backlog = res.cves.filter(c => c.backlog);
  const openEnd = res.cves.filter(v => v.closedAt == null || v.closedAt >= res.tEnd);
  const em = res.updates.filter(u => u.kind === "emerg").length;
  let eolMonths = 0;
  for (let m = res.t0; m < res.tEnd; m = addMonths(m, 1)) comps.forEach(c => { const g = segAt(res, c.id, m); if (g && (m >= g.ver.pe || m < g.frozenUntil)) eolMonths++; });
  const cap = p.fte * 140 * (bucketKind === "q" ? 3 : 1), over = bk.filter(b => b.total > cap).length;
  const peak = bk.reduce((a, b) => b.total > a.total ? b : a, bk[0] || { total: 0, label: "—" });
  const ih = issues.filter(i => i.sev === "high").length, im = issues.filter(i => i.sev === "med").length;
  const K = [["Łączna praca", nf.format(tot) + " h", `${p.horizon} lat · średnio ${nf1.format(tot / months / 140)} FTE`],
    ["Nowe podatności (symulowane)", nf.format(nw.length), `w tym krytycznych: ${nw.filter(c => c.sev === "crit").length}`]];
  if (p.scen === "old") K.push(["Zaległe podatności na start", nf.format(backlog.length), `od ${W.lastPatch}; krytyczne: ${backlog.filter(c => c.sev === "crit").length}`]);
  K.push(["Otwarte na koniec horyzontu", nf.format(openEnd.length), `krytyczne i wysokie: ${openEnd.filter(v => v.sev === "crit" || v.sev === "high").length}`],
    ["Mitygacje", nf.format(res.cves.filter(c => c.mitig).length), p.mitOn ? `skuteczne: ${res.cves.filter(c => c.mitigatedAt != null).length} · nieskuteczne lub niemożliwe: ${res.cves.filter(c => c.mitigFail).length}` : "wyłączone w parametrach"],
    ["Aktualizacje awaryjne", nf.format(em), `planowe: ${res.updates.filter(u => u.kind !== "emerg").length}`],
    ["Migracje wersji", nf.format(res.migs.length), plan && p.mode === "plan" ? `plan: ${nf.format(plan.total)} h do ${fmtM(plan.end)}` : p.mode === "noupd" ? "brak — serwer bez aktualizacji" : p.autoMig ? `${p.lead} mies. przed końcem poprawek` : "automatyczne wyłączone"],
    ["Produkt niebezpieczny", dz.first != null ? fmtM(dz.first) : "—", (dz.first != null ? (dz.intervals[0].open ? "do końca horyzontu" : "do " + fmtM(addMonths(dz.intervals[0].to, -1))) + (dz.intervals.length > 1 ? ` (+${dz.intervals.length - 1} okr.)` : "") + " · " : "") + "bez płatnego wsparcia i nowych wersji: " + (dzAlt.none.first != null ? "od " + fmtM(dzAlt.none.first) : "nie w horyzoncie")],
    ["Składniko‑miesiące bez poprawek", nf.format(eolMonths), eolMonths ? "EOL, niewykupione wsparcie lub brak aktualizacji" : "pełne pokrycie poprawkami"],
    ["Problemy zgodności", `${ih} / ${im}`, "wysokie / średnie"],
    ["Szczyt obciążenia", nf.format(peak.total) + " h", `${peak.label} · przekroczeń pojemności: ${over}`]);
  $("kpis").innerHTML = K.map(([k, v, d]) => `<div class="kpi"><div class="k">${k}</div><div class="v">${v}</div><div class="d">${esc(d)}</div></div>`).join("");
}
function sevBadge(s) { return `<span class="badge"><i style="background:${ISS_C[s]}"></i>${ISS_N[s]}</span>`; }
function renderPlan(p, plan, res, issues) {
  const notesHtml = ns => ns.length ? `<ul>${ns.map(n => `<li>${n.s !== "info" ? `<b style="color:${ISS_C[n.s]}">${ISS_N[n.s]}:</b> ` : ""}${esc(n.t)}</li>`).join("")}</ul>` : '<span class="muted">—</span>';
  const risk = ns => { const r = ns.some(n => n.s === "high") ? "high" : ns.some(n => n.s === "med") ? "med" : "low"; return sevBadge(r); };
  if (p.scen === "old" && plan) {
    $("planTitle").textContent = "Zalecany plan modernizacji — " + (p.strat === "inplace" ? "aktualizacja w miejscu" : "nowy serwer i przełączenie");
    $("planHint").innerHTML = `Łącznie ok. <b>${nf.format(plan.total)} h</b>, zakończenie ok. <b>${fmtM(plan.end)}</b> (${Math.round((plan.end - p.start) / MON)} mies. przy ${nf1.format(p.fte)} FTE, ok. 60% czasu na modernizację).` +
      (p.mode === "noupd" ? " <b>Symulacja pokazuje teraz stan bez aktualizacji</b> — plan jest rekomendacją." : " Plan jest uwzględniony w symulacji.");
    const rows = [plan.P0, plan.P1, ...plan.steps];
    $("planTable").innerHTML = `<tr><th>Okres</th><th>Etap</th><th>Zmiana wersji</th><th class="num">Godziny</th><th>Ryzyko</th><th>Uwagi i zgodność</th></tr>` + rows.map(r => {
      return `<tr><td>${fmtM(r.start)} – ${fmtM(r.end)}${r.manual ? '<div class="muted" style="font-size:11.5px">data ustawiona ręcznie</div>' : ""}</td><td style="white-space:normal;min-width:200px">${esc(r.name)}</td><td>${r.from || r.to ? `${esc(r.from)} → <b>${esc(r.to)}</b>` : "—"}</td><td class="num">${nf.format(r.hours)}</td><td>${r.kind === "phase" ? sevBadge("info") : risk(r.notes)}</td><td class="wrapc">${notesHtml(r.notes)}</td></tr>`;
    }).join("") + (plan.steps.length ? "" : `<tr><td colspan="6" class="muted">Wszystkie składniki są już w zalecanych seriach — wystarczy doinstalować poprawki.</td></tr>`);
  } else {
    $("planTitle").textContent = "Plan prac: migracje w horyzoncie symulacji";
    $("planHint").textContent = p.autoMig ? `Migracje ${p.lead} mies. przed końcem dostępnych poprawek (darmowych albo — gdy wykupione — płatnych). Dla nowego wdrożenia między migracjami wystarczą regularne aktualizacje.` : "Automatyczne migracje są wyłączone — składniki po EOL pozostają bez poprawek.";
    const nm = id => comps.find(c => c.id === id).name;
    const rows = res.migs.slice().sort((a, b) => a.start - b.start);
    $("planTable").innerHTML = `<tr><th>Okres</th><th>Składnik</th><th>Zmiana wersji</th><th class="num">Godziny</th><th>Ryzyko</th><th>Uwagi i zgodność</th></tr>` + (rows.map(m => {
      const c = comps.find(x => x.id === m.comp), mn = res.migNotes.find(x => x.comp === m.comp && x.at === m.end);
      const altDef = m.alt ? (FAM[c.fam].alts || []).find(a => a.to === m.toFam) : null;
      const ns = (altDef ? altDef.notes.map(n => ({ ...n })) : mn ? mn.items.map(b => ({ s: b.s, t: b.t })) : []).concat(FAM[m.toFam] && FAM[m.toFam].mnote ? [{ s: "info", t: FAM[m.toFam].mnote }] : []);
      const hrs = res.work.filter(w => w.comp === m.comp && w.type === "mig" && w.t >= m.start - MON && w.t <= m.end).reduce((s, w) => s + w.h, 0);
      return `<tr><td>${fmtM(m.start)} – ${fmtM(m.end)}</td><td>${esc(nm(m.comp))}${m.alt ? '<div class="muted" style="font-size:11.5px">zamiana na darmowy odpowiednik</div>' : ""}</td><td>${esc(m.from)} → <b>${esc(m.to)}</b></td><td class="num">${nf.format(hrs)}</td><td>${risk(ns.filter(n => n.s !== "info"))}</td><td class="wrapc">${notesHtml(ns)}</td></tr>`;
    }).join("") || `<tr><td colspan="6" class="muted">Brak migracji w horyzoncie.</td></tr>`);
  }
  $("issues").innerHTML = issues.length ? issues.map(i => `<li>${sevBadge(i.sev)}<div><b>${esc(i.comp)}</b> <span class="who">— ${esc(i.where)}</span><div>${esc(i.text)}</div></div></li>`).join("") : `<li><span class="muted">Nie wykryto znanych problemów zgodności dla wybranej konfiguracji.</span></li>`;
}
function renderSummary(res) {
  let h = `<tr><th>Składnik</th><th>Wersje w horyzoncie</th><th>Status na start</th><th class="num">Akt. planowe</th><th class="num">Akt. awaryjne</th><th class="num">Podatności kryt./wys./śr./nis.</th><th class="num">Otwarte na koniec</th>` + TYPES.map(([, n]) => `<th class="num">${n} (h)</th>`).join("") + `<th class="num">Razem (h)</th></tr>`;
  const rows = comps.map(c => {
    const segs = res.segs.filter(g => g.comp === c.id), w = res.work.filter(x => x.comp === c.id), byT = {};
    TYPES.forEach(([k]) => byT[k] = w.filter(x => x.type === k).reduce((s, x) => s + x.h, 0));
    const tot = Object.values(byT).reduce((a, b) => a + b, 0), cv = res.cves.filter(x => x.comp === c.id), cnt = k => cv.filter(x => x.sev === k).length;
    const st = compSt(c, res.t0), up = res.updates.filter(u => u.comp === c.id);
    const open = cv.filter(v => v.closedAt == null || v.closedAt >= res.tEnd).length;
    return { tot, html: `<tr><td>${esc(c.name)}</td><td>${segs.map(g => esc(g.label)).join(" → ")}</td><td><span class="badge"><i style="background:${ST_C[st]}"></i>${ST_S[st]}</span></td>
      <td class="num">${up.filter(u => u.kind !== "emerg").length}</td><td class="num">${up.filter(u => u.kind === "emerg").length}</td><td class="num">${cnt("crit")} / ${cnt("high")} / ${cnt("med")} / ${cnt("low")}</td><td class="num">${open}</td>` +
      TYPES.map(([k]) => `<td class="num">${nf.format(byT[k])}</td>`).join("") + `<td class="num"><b>${nf.format(tot)}</b></td></tr>` };
  }).sort((a, b) => b.tot - a.tot);
  $("summary").innerHTML = h + rows.map(r => r.html).join("");
}
function renderMiles(res, plan, p) {
  const lim = addMonths(res.t0, 24), ev = [], seen = new Set(), nm = id => (comps.find(c => c.id === id) || { name: id }).name;
  res.segs.forEach(g => [["eos", g.eos, "Koniec pełnego wsparcia (EOS)", "var(--warning)"], ["eol", g.eol, "Koniec wsparcia (EOL)", "var(--critical)"]].forEach(([k, t, n, col]) => {
    const key = g.comp + k + t; if (seen.has(key)) return; seen.add(key);
    if (t >= addMonths(res.t0, -12) && t <= lim && (g.eos !== g.eol || k === "eol")) ev.push({ t, txt: n + (k === "eos" && g.ver.paidExt ? " — dalej płatne: " + g.ver.paidExt : ""), comp: nm(g.comp) + " " + g.label, col, past: t < res.t0 });
  }));
  res.segs.forEach(g => { const e = g.ver.esu; if (e && e >= addMonths(res.t0, -12) && e <= lim && !seen.has(g.comp + "esu" + e)) { seen.add(g.comp + "esu" + e); ev.push({ t: e, txt: "Koniec płatnego wsparcia: " + (g.ver.esuName || ""), comp: nm(g.comp) + " " + g.label, col: "var(--critical)", past: e < res.t0 }); } });
  if (plan && p.mode === "plan") plan.steps.forEach(st => { if (st.start <= lim) ev.push({ t: st.start, txt: "Plan: " + st.name.replace(/:.*$/, "") + (st.to ? " → " + st.to : ""), comp: st.comp ? nm(st.comp) : "Całość", col: "var(--s5)" }); });
  else res.migs.forEach(m => { if (m.start <= lim) ev.push({ t: m.start, txt: "Start migracji " + m.from + " → " + m.to, comp: nm(m.comp), col: "var(--s5)" }); });
  res.cves.filter(c => c.t <= lim && !c.backlog && (c.sev === "crit" || c.wave)).forEach(c => ev.push({ t: c.t, txt: (c.wave ? "Fala 0‑day " : "Podatność krytyczna ") + c.id + (c.supported ? "" : " (po EOL)"), comp: nm(c.comp), col: "var(--critical)" }));
  ev.sort((a, b) => a.t - b.t);
  $("miles").innerHTML = `<tr><th>Data</th><th>Zdarzenie</th><th>Składnik</th></tr>` + (ev.map(e => `<tr${e.past ? ' class="muted"' : ""}><td>${fmt(e.t)}${e.past ? " (minęło)" : ""}</td><td><span class="badge"><i style="background:${e.col}"></i>${esc(e.txt)}</span></td><td>${esc(e.comp)}</td></tr>`).join("") || `<tr><td colspan="3" class="muted">Brak zdarzeń</td></tr>`);
}


/* ================= darmowe odpowiedniki ================= */
function renderAlts(p) {
  const cand = comps.filter(c => FAM[c.fam] && (FAM[c.fam].alts || []).some(a => FAM[a.to]));
  if (!cand.length) { $("altBox").innerHTML = `<p class="hint" style="margin:0">Wybrane składniki nie mają w katalogu darmowych odpowiedników.</p>`; return; }
  $("altBox").innerHTML = `<div class="alts">` + cand.map(c => {
    const opts = FAM[c.fam].alts.filter(a => FAM[a.to]);
    const cur = (W.alts && W.alts[c.fam]) || "";
    return `<label class="pick ${cur ? "on" : ""}"><span class="top">${esc(c.name)} ${esc(c.ver)}</span>
      <select data-alt="${c.fam}"><option value="">Pozostaw (aktualizuj w obrębie produktu)</option>${opts.map(a => `<option value="${a.to}" ${cur === a.to ? "selected" : ""}>Zamień na: ${esc(FAM[a.to].name)} (ok. ${nf.format(a.h)} h)</option>`).join("")}</select>
      <span class="st">${cur ? (p.scen === "old" ? "zamiana w planie modernizacji" : "odpowiednik od początku (adaptacja ok. 3 mies.)") : "bez zmian"}</span></label>`;
  }).join("") + `</div>`;
}
$("altBox").addEventListener("change", e => { const f = e.target.dataset.alt; if (!f) return; W.alts = W.alts || {}; if (e.target.value) W.alts[f] = e.target.value; else delete W.alts[f]; run(); });

/* ================= aktualne podatności (prawdziwe dane CISA KEV) ================= */
function renderKev() {
  const V = DATA.vulnerabilities || {}, cat = V.kevCatalog || {};
  const fams = [...new Set(comps.filter(c => FAM[c.fam]).map(c => c.fam).concat(Object.values(W.alts || {})))].filter(f => FAM[f]);
  $("kevHint").innerHTML = `Prawdziwe podatności aktywnie wykorzystywane w atakach wg katalogu CISA KEV${cat.version ? " (wersja " + esc(cat.version) + ")" : ""}; dane z ${esc(V.updated || "—")}. Pokazane są składniki wybranego produktu. Nie są to podatności symulowane (SIM‑…).`;
  $("kevTable").innerHTML = `<tr><th>Składnik</th><th class="num">Wpisy KEV z 2 lat</th><th class="num">Założenie symulacji (podatności/rok)</th><th>Najnowsze wpisy</th></tr>` + fams.map(f => {
    const k = FAM[f].kevData;
    const items = k && k.items && k.items.length ? `<ul class="kev">${k.items.slice(0, 4).map(x => `<li><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(x.id)}" target="_blank" rel="noopener">${esc(x.id)}</a> · ${esc(x.added)}${x.ransomware ? ' · <b style="color:var(--critical)">ransomware</b>' : ""}<div class="muted">${esc(x.name)}</div></li>`).join("")}</ul>` : `<span class="muted">brak wpisów w KEV${(FAM[f].kevMatch || []).length ? "" : " (brak mapowania)"}</span>`;
    return `<tr><td>${esc(FAM[f].name)}</td><td class="num">${k ? k.count2y : "—"}</td><td class="num">${nf1.format(FAM[f].cve)}</td><td class="wrapc">${items}</td></tr>`;
  }).join("");
}

/* ================= dane i ich aktualizacja ================= */
let syncResult = null;
function renderDataPanel() {
  const d = DATA, row = (n, label, upd, extra) => `<tr><td><b>${label}</b><div class="muted" style="font-size:11.5px">data/${n}.json</div></td><td>${esc(upd || "—")}</td><td>${d.local[n] ? '<span class="badge"><i style="background:var(--warning)"></i>zmienione w tej przeglądarce</span>' : '<span class="badge"><i style="background:var(--good)"></i>z serwera</span>'}</td><td class="wrapc">${extra}</td></tr>`;
  const nVer = Object.values(d.lifecycle.families || {}).reduce((s, a) => s + a.length, 0);
  $("dataTable").innerHTML = `<tr><th>Plik</th><th>Aktualizacja</th><th>Źródło w tej sesji</th><th>Zawartość</th></tr>` +
    row("products", "Produkty", d.products.updated, `${Object.keys(d.products.families).length} produktów, ${d.products.templates.length} szablonów, licencje, zmiany niekompatybilne, darmowe odpowiedniki`) +
    row("lifecycle", "Daty wsparcia", d.lifecycle.updated, `${nVer} wersji; źródło: endoflife.date + ręczne`) +
    row("vulnerabilities", "Podatności", d.vulnerabilities.updated, `założone tempo podatności (do symulacji) i wpisy CISA KEV${d.vulnerabilities.kevCatalog && d.vulnerabilities.kevCatalog.version ? " " + esc(d.vulnerabilities.kevCatalog.version) : ""}`);
  $("dataReset").disabled = !Object.keys(d.local).length;
  const r = syncResult;
  if (!r) { $("syncOut").innerHTML = ""; return; }
  $("syncOut").innerHTML = (r.error ? `<p style="color:var(--critical)">${esc(r.error)}</p>` : "") +
    (r.changes ? `<p><b>${r.changes.length ? r.changes.length + " zmian w datach wsparcia" : "Daty wsparcia są aktualne"}</b> (endoflife.date, ${esc(r.at)}).</p>` : "") +
    (r.changes && r.changes.length ? `<div class="scroll" style="max-height:280px;overflow-y:auto"><table><tr><th>Produkt</th><th>Wersja</th><th>Pole</th><th>Było</th><th>Jest</th></tr>${r.changes.map(c => `<tr><td>${esc(c.name)}</td><td>${esc(c.label)}</td><td>${esc(c.field)}</td><td>${esc(c.from)}</td><td><b>${esc(c.to)}</b></td></tr>`).join("")}</table></div>
      <div class="row" style="margin-top:8px"><button id="syncApply" class="primary">Zastosuj w tej przeglądarce</button><button id="syncDownload">Pobierz zaktualizowany lifecycle.json</button></div>` : "") +
    (r.newCycles && r.newCycles.length ? `<p class="hint" style="margin-top:8px">Nowe wydania do dodania ręcznie w lifecycle.json: ${r.newCycles.map(c => `${esc(c.name)} ${esc(c.cycle)} (${esc(c.rel)})`).join(", ")}.</p>` : "") +
    (r.errors && r.errors.length ? `<p class="hint">Ostrzeżenia: ${r.errors.map(esc).join("; ")}</p>` : "");
}
function download(name, text) { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: "application/json" })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
function reloadData(d) { buildFam(d); buildComps(); renderWizard(); renderEditor(); run(); }
$("syncBtn").onclick = async () => {
  $("syncBtn").disabled = true; $("syncOut").innerHTML = `<p class="hint">Pobieranie z endoflife.date…</p>`;
  try {
    const fetchJson = async url => { const r = await fetch(url); if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); };
    const r = await syncLifecycle(DATA.products, DATA.lifecycle, fetchJson, todayStr());
    syncResult = { ...r, at: todayStr() };
  } catch (e) { syncResult = { error: "Nie udało się pobrać danych: " + (e.message || e) }; }
  $("syncBtn").disabled = false; renderDataPanel();
};
$("syncOut").addEventListener("click", e => {
  if (!syncResult || !syncResult.lifecycle) return;
  if (e.target.id === "syncApply") { writeOverride("lifecycle", syncResult.lifecycle); DATA.lifecycle = syncResult.lifecycle; DATA.local.lifecycle = true; syncResult = null; reloadData(DATA); }
  if (e.target.id === "syncDownload") download("lifecycle.json", formatJson(syncResult.lifecycle));
});
$("dataFile").addEventListener("change", async e => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const obj = JSON.parse(await f.text());
    const kind = obj.templates && obj.families ? "products" : obj.fields && obj.families ? "lifecycle" : obj.families && Object.values(obj.families).some(x => x && "rate" in x) ? "vulnerabilities" : null;
    if (!kind) throw new Error("nie rozpoznano pliku (oczekiwano products.json, lifecycle.json lub vulnerabilities.json)");
    const test = { ...DATA, [kind]: obj }; buildFam(test); // walidacja
    writeOverride(kind, obj); DATA[kind] = obj; DATA.local[kind] = true; syncResult = null; reloadData(DATA);
    alert("Wczytano " + kind + ".json — dane obowiązują w tej przeglądarce.");
  } catch (err) { buildFam(DATA); alert("Nie wczytano pliku: " + (err.message || err)); }
  e.target.value = "";
});
$("dataReset").onclick = () => { DATA_FILES.forEach(n => { writeOverride(n, null); if (DATA.local[n]) DATA[n] = DATA.server[n]; }); DATA.local = {}; syncResult = null; reloadData(DATA); };
document.querySelectorAll("[data-dl]").forEach(b => b.onclick = () => download(b.dataset.dl + ".json", formatJson(DATA[b.dataset.dl])));

/* ================= daty i czasochłonność migracji (suwaki) ================= */
const monthStr = t => fmt(t).slice(0, 8) + "01";
function renderMigPanel(res, p) {
  const months = p.horizon * 12;
  if (p.mode === "noupd") { $("migBox").innerHTML = `<p class="hint" style="margin:0">W trybie „bez aktualizacji” migracje nie są symulowane — przełącz „Z planem modernizacji”, aby ustawiać ich daty.</p>`; return; }
  const rows = comps.filter(c => c.fam !== "custom" && !followsOs(c) && !(FAM[c.fam] && FAM[c.fam].noPatches && !altFor(c)));
  $("migBox").innerHTML = rows.map(c => {
    const o = migOvOf(c), mlist = res.migs.filter(m => m.comp === c.id), m = mlist[mlist.length && p.mode === "plan" ? Math.max(0, mlist.filter(x => x.planned).length - 1) : 0];
    const cur = o.at ? D(o.at) : m ? m.end : null;
    const off = cur ? Math.min(months, Math.max(1, Math.round((cur - res.t0) / MON))) : months;
    const a = altFor(c), autoH = a ? a.h : c.mig;
    const what = m ? `${esc(m.from)} → ${esc(m.to)}` : "brak migracji w horyzoncie — przesuń suwak, aby ją zaplanować";
    const linked = comps.filter(x => followsOs(x) && c.cat === "os").map(x => x.name.replace(/ \(.*\)$/, ""));
    return `<div class="migrow" data-mig="${c.id}">
      <div class="nm"><b>${esc(c.name)}</b><span class="muted">${what}${linked.length ? ` · razem z: ${esc(linked.join(", "))}` : ""}</span></div>
      <label class="sl"><span>Data migracji (go‑live): <b class="mv">${cur ? fmtM(cur) : "—"}</b> <span class="muted">${o.at ? "ręcznie" : "automatycznie"}</span></span>
        <input type="range" min="1" max="${months}" step="1" value="${off}" data-k="at" aria-label="Data migracji: ${esc(c.name)}"></label>
      <label class="hh"><span>Godziny migracji</span><input type="number" min="0" step="10" value="${o.h != null ? esc(o.h) : ""}" placeholder="${nf.format(autoH)}" data-k="h"></label>
      <button data-k="reset" ${o.at || o.h != null ? "" : "disabled"} title="Wróć do wartości automatycznych">Automatycznie</button>
    </div>`;
  }).join("") || `<p class="hint" style="margin:0">Brak składników, które można migrować.</p>`;
}
$("migBox").addEventListener("input", e => {
  if (e.target.dataset.k !== "at") return;
  const row = e.target.closest("[data-mig]"); row.querySelector(".mv").textContent = fmtM(addMonths(startT(), +e.target.value));
});
$("migBox").addEventListener("change", e => {
  const row = e.target.closest("[data-mig]"); if (!row) return;
  const id = row.dataset.mig; W.migOv = W.migOv || {}; const o = W.migOv[id] = W.migOv[id] || {};
  if (e.target.dataset.k === "at") o.at = monthStr(addMonths(startT(), +e.target.value));
  if (e.target.dataset.k === "h") { if (e.target.value === "") delete o.h; else o.h = Math.max(0, +e.target.value); }
  if (!o.at && o.h == null) delete W.migOv[id];
  run();
});
$("migBox").addEventListener("click", e => {
  if (e.target.dataset.k !== "reset") return;
  const id = e.target.closest("[data-mig]").dataset.mig; if (W.migOv) delete W.migOv[id]; run();
});

/* ================= uruchomienie ================= */
let bucketKind = "q", lastRes = null;
function P() {
  return { start: startT(), horizon: +$("horizon").value, trend: $("trend").value, growth: +$("growth").value / 100, seed: +$("seed").value || 1,
    slaC: +$("slaC").value || 7, slaH: +$("slaH").value || 30, fte: +$("fte").value || 1, reg: +$("reg").value / 100, autoMig: $("autoMig").checked,
    lead: +$("lead").value || 0, waves: $("waves").checked, mitOn: $("mitOn").checked, mitEff: +$("mitEff").value / 100, mitDays: Math.max(0, +$("mitDays").value || 0), buy: W.buy !== "no", scen: W.scen, mode: W.scen === "new" ? "new" : W.oldMode, strat: W.strat, lastPatch: D(W.lastPatch) };
}
function syncLabels() {
  $("horizonV").textContent = $("horizon").value + " lat"; $("growthV").textContent = $("growth").value + "%"; $("regV").textContent = $("reg").value + "%"; $("mitEffV").textContent = $("mitEff").value + "%"; $("mitEff").disabled = $("mitDays").disabled = !$("mitOn").checked;
  $("growth").disabled = $("trend").value === "const"; $("lead").disabled = !$("autoMig").checked;
}
function save() {
  try { localStorage.setItem("supsim4", JSON.stringify({ W, comps, uid, ui: ["start", "horizon", "trend", "growth", "seed", "slaC", "slaH", "fte", "reg", "lead", "mitEff", "mitDays"].reduce((o, k) => (o[k] = $(k).value, o), { autoMig: $("autoMig").checked, waves: $("waves").checked, mitOn: $("mitOn").checked }) })); } catch (e) {}
}
function restore() {
  try {
    const s = JSON.parse(localStorage.getItem("supsim4") || "null"); if (!s || !s.W || !s.comps) return false;
    W = s.W; comps = s.comps; uid = s.uid || 100;
    for (const k in s.ui) { if (k === "autoMig" || k === "waves" || k === "mitOn") $(k).checked = s.ui[k]; else if ($(k)) $(k).value = s.ui[k]; }
    if (!FAM[W.os.f]) return false;
    return true;
  } catch (e) { return false; }
}
function run() {
  syncLabels();
  const p = P();
  if (!comps.length) return;
  const plan = p.scen === "old" ? computePlan(p) : null;
  p.planData = plan;
  const res = simulate(p);
  const resConst = simulate(p, { trend: "const" });
  let alt = res, altName = $("trend").selectedOptions[0].text + " (" + Math.round(p.growth * 100) + "%/rok)";
  if (p.trend === "const") { alt = simulate({ ...p, growth: 0.25 }, { trend: "exp" }); altName = "Rosnący wykładniczo (25%/rok)"; }
  const altMode = p.mode === "noupd" ? "plan" : "noupd";
  const resAltMode = simulate(p, { mode: altMode });
  const altModeName = altMode === "plan" ? "Z planem modernizacji" : "Bez aktualizacji";
  lastRes = res;
  const issues = compatIssues(p, plan, res);
  const dz = dangerSeries(res, p);
  const dzNoBuy = p.buy ? dangerSeries(simulate(p, { buy: false }), p) : dz;
  const dzNone = dangerSeries(simulate(p, { buy: false, noMig: true }), p);
  const dzAlt = { noBuy: dzNoBuy, none: dzNone };
  const bk = buckets(res, bucketKind);
  renderKpis(res, p, bk, plan, issues, dz, dzAlt);
  renderPurchases(res, p, plan, dz, dzAlt);
  renderPlan(p, plan, res, issues);
  renderTimeline(res, dz);
  renderExposure(res, resAltMode, altModeName, p);
  renderCves(res, bk);
  renderEffort(res, p, bk);
  renderCompare(resConst, alt, altName);
  renderGraph(res);
  renderMiles(res, plan, p);
  renderSummary(res);
  renderAlts(p); renderMigPanel(res, p); renderKev(); renderDataPanel();
  save();
}
["horizon", "trend", "growth", "seed", "slaC", "slaH", "fte", "reg", "autoMig", "lead", "waves", "mitOn", "mitEff", "mitDays"].forEach(id => $(id).addEventListener("input", run));
$("start").addEventListener("change", () => { renderWizard(); run(); });
$("reseed").onclick = () => { $("seed").value = Math.floor(Math.random() * 99999); run(); };
$("bucketTabs").addEventListener("click", e => { const b = e.target.closest("button"); if (!b) return; bucketKind = b.dataset.b; document.querySelectorAll("#bucketTabs button").forEach(x => x.classList.toggle("on", x === b)); run(); });
$("csvBtn").onclick = () => {
  if (!lastRes) return;
  const nm = id => { const c = comps.find(x => x.id === id); return c ? c.name : id; }, tn = Object.fromEntries(TYPES.map(([k, n]) => [k, n]));
  const lines = [["data", "skladnik", "wersja", "typ_pracy", "godziny", "opis"].join(";")];
  lastRes.work.forEach(w => lines.push([fmt(w.t), nm(w.comp), w.ver, tn[w.type], w.h.toFixed(2).replace(".", ","), w.desc].map(v => '"' + String(v).replace(/"/g, '""') + '"').join(";")));
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob(["﻿" + lines.join("\n")], { type: "text/csv;charset=utf-8" })); a.download = "symulacja-prac.csv"; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};
const THEMES = ["auto", "light", "dark"], TN = { auto: "auto", light: "jasny", dark: "ciemny" };
let theme = "auto"; try { theme = localStorage.getItem("supsim-theme") || "auto"; } catch (e) {}
function applyTheme() { if (theme === "auto") document.documentElement.removeAttribute("data-theme"); else document.documentElement.setAttribute("data-theme", theme); $("themeBtn").textContent = "Motyw: " + TN[theme]; }
$("themeBtn").onclick = () => { theme = THEMES[(THEMES.indexOf(theme) + 1) % 3]; try { localStorage.setItem("supsim-theme", theme); } catch (e) {} applyTheme(); };
let rt; addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(run, 150); });

applyTheme();
$("appVer").textContent = "· wersja strony " + APP_VERSION;
$("start").value = todayStr();
try {
  buildFam(await loadData());
  if (!restore() || !FAM[W.os.f]) { W = defaultW(); applyTemplate("javaee"); }
  W.alts = W.alts || {}; W.migOv = W.migOv || {};
  buildComps();
  renderWizard(); renderEditor(); run();
  $("loading").remove();
} catch (e) {
  console.error(e);
  $("loading").innerHTML = `<b>Nie udało się wczytać danych symulatora.</b> ${esc(e.message || e)}<br>Strona wczytuje pliki data/*.json, więc musi być otwarta przez serwer WWW (np. GitHub Pages albo lokalnie: <code>python3 -m http.server</code> w katalogu repozytorium), a nie bezpośrednio z dysku.`;
}
