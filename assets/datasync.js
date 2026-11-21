// Wspólna logika aktualizacji danych — używana przez stronę (przeglądarka) i skrypt tools/update-data.mjs (Node).
// Nie zależy od DOM ani od Node; pobieranie danych przekazuje się jako funkcję.

export const EOL_API = "https://endoflife.date/api/";
export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const isDate = v => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
const clone = o => JSON.parse(JSON.stringify(o));

/**
 * Mapuje cykl z endoflife.date na pola wersji (rel, eos, eol, esu) zależnie od trybu rodziny.
 *  default — eos ← support, eol ← eol, esu ← extendedSupport (np. Windows, RHEL, Debian)
 *  premier — eos ← eol (Premier), eol ← extendedSupport (Oracle DB, Oracle JDK)
 *  ubuntu  — eos ← eol (standardowe wsparcie), eol ← extendedSupport (ESM / Ubuntu Pro)
 */
export function mapCycle(mode, v, c) {
  const n = { ...v };
  if (isDate(c.releaseDate)) n.rel = c.releaseDate;
  if (mode === "premier" || mode === "ubuntu") {
    if (isDate(c.eol)) n.eos = c.eol;
    if (isDate(c.extendedSupport)) n.eol = c.extendedSupport;
    else if (n.eol && n.eos > n.eol) n.eol = n.eos;
  } else {
    const single = v.eos === v.eol;
    if (isDate(c.eol)) n.eol = c.eol;
    if (isDate(c.support)) n.eos = c.support;
    else if (single && isDate(c.eol)) n.eos = c.eol;
    if (n.eos > n.eol) n.eos = n.eol;
    if (isDate(c.extendedSupport) && c.extendedSupport > n.eol) n.esu = c.extendedSupport;
  }
  if (n.fc && isDate(c.eol)) delete n.fc; // daty potwierdzone przez źródło
  return n;
}

/** Porównuje lifecycle.json z endoflife.date. fetchJson(url) → Promise<obiekt>. */
export async function syncLifecycle(products, lifecycle, fetchJson, today) {
  const out = clone(lifecycle), changes = [], newCycles = [], errors = [];
  for (const [fam, meta] of Object.entries(products.families)) {
    const sync = meta.sync; if (!sync || !out.families[fam]) continue;
    let cycles;
    try { cycles = await fetchJson(EOL_API + sync.slug + ".json"); } catch (e) { errors.push(`${fam} (${sync.slug}): ${e.message || e}`); continue; }
    const byCycle = new Map(cycles.map(c => [String(c.cycle), c]));
    const known = new Set();
    out.families[fam] = out.families[fam].map(v => {
      if (!v.cycle) return v;
      known.add(v.cycle);
      const c = byCycle.get(String(v.cycle)); if (!c) { errors.push(`${fam}: brak cyklu „${v.cycle}” w ${sync.slug}`); return v; }
      const n = mapCycle(sync.mode, v, c);
      // pola pomijane (np. cykle Service Packów albo daty wydania dystrybucji zamiast samej wersji)
      for (const k of [...(sync.skip || []), ...(v.syncSkip || [])]) { if (k in v) n[k] = v[k]; else delete n[k]; }
      for (const k of ["rel", "eos", "eol", "esu", "fc"]) if (n[k] !== v[k]) changes.push({ fam, name: meta.name, label: v.l, field: k, from: v[k] ?? "—", to: n[k] ?? "—" });
      return n;
    });
    // nowe wydania, których nie ma w katalogu (tylko nowsze niż najnowsza znana wersja; przy rodzinach z LTS — tylko LTS)
    const newest = out.families[fam].reduce((m, v) => v.rel && v.rel > m ? v.rel : m, "");
    const hasLts = cycles.some(c => c.lts === true);
    const ignore = new Set((sync.ignore || []).map(String));
    cycles.filter(c => !known.has(String(c.cycle)) && !ignore.has(String(c.cycle)) && isDate(c.releaseDate) && c.releaseDate > newest && (!hasLts || c.lts === true) && (!today || c.releaseDate <= today))
      .forEach(c => newCycles.push({ fam, name: meta.name, cycle: String(c.cycle), rel: c.releaseDate, eos: isDate(c.support) ? c.support : null, eol: isDate(c.eol) ? c.eol : null }));
  }
  if (changes.length) out.updated = today || new Date().toISOString().slice(0, 10);
  return { lifecycle: out, changes, newCycles, errors };
}

/** Aktualizuje vulnerabilities.json na podstawie katalogu CISA KEV. */
export function syncKev(products, vulns, kev, today, perFamily = 8) {
  const out = clone(vulns), t = today || new Date().toISOString().slice(0, 10);
  const since = new Date(Date.parse(t) - 730 * 86400000).toISOString().slice(0, 10);
  const list = kev.vulnerabilities || [];
  const summary = [];
  for (const [fam, meta] of Object.entries(products.families)) {
    const pats = (meta.kevMatch || []).map(m => [new RegExp(m.vendor, "i"), m.product ? new RegExp(m.product, "i") : null]);
    if (!pats.length) continue;
    const hits = list.filter(x => pats.some(([v, p]) => v.test(x.vendorProject) && (!p || p.test(x.product))))
      .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
    const fv = out.families[fam] || (out.families[fam] = { rate: 2 });
    const prev = fv.kev && fv.kev.count2y || 0;
    fv.kev = {
      count2y: hits.filter(x => x.dateAdded >= since).length,
      total: hits.length,
      items: hits.slice(0, perFamily).map(x => ({ id: x.cveID, name: x.vulnerabilityName, product: `${x.vendorProject} ${x.product}`, added: x.dateAdded,
        ransomware: x.knownRansomwareCampaignUse === "Known", desc: (x.shortDescription || "").slice(0, 240) }))
    };
    summary.push({ fam, name: meta.name, count2y: fv.kev.count2y, prev, latest: fv.kev.items[0] ? fv.kev.items[0].added : null });
  }
  out.updated = t;
  out.kevCatalog = { version: kev.catalogVersion || null, released: kev.dateReleased || null };
  return { vulnerabilities: out, summary };
}

/** Czytelny zapis JSON: proste obiekty (np. wersje) w jednej linii, łatwe do ręcznej edycji i przeglądania w diffie. */
export function formatJson(obj) {
  const flat = v => v && typeof v === "object" && !Array.isArray(v) && Object.values(v).every(x => x === null || typeof x !== "object");
  const ser = (v, ind) => {
    const pad = " ".repeat(ind), pad2 = " ".repeat(ind + 2);
    if (Array.isArray(v)) {
      if (!v.length) return "[]";
      if (v.every(x => x === null || typeof x !== "object")) return JSON.stringify(v);
      return "[\n" + v.map(x => pad2 + (flat(x) ? JSON.stringify(x) : ser(x, ind + 2))).join(",\n") + "\n" + pad + "]";
    }
    if (v && typeof v === "object") {
      const ks = Object.keys(v); if (!ks.length) return "{}";
      return "{\n" + ks.map(k => pad2 + JSON.stringify(k) + ": " + ser(v[k], ind + 2)).join(",\n") + "\n" + pad + "}";
    }
    return JSON.stringify(v);
  };
  return ser(obj, 0) + "\n";
}
