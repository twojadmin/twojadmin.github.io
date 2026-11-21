#!/usr/bin/env node
// Aktualizuje pliki danych symulatora:
//   data/lifecycle.json       — daty wsparcia z endoflife.date (wersje z polem „cycle”)
//   data/vulnerabilities.json — podatności aktywnie wykorzystywane z katalogu CISA KEV
//
// Użycie:
//   node tools/update-data.mjs                 # oba źródła, zapis plików
//   node tools/update-data.mjs --dry-run       # tylko raport, bez zapisu
//   node tools/update-data.mjs --only lifecycle|kev
//   node tools/update-data.mjs --kev-file kev.json   # katalog KEV z pliku (bez pobierania)
//   node tools/update-data.mjs --report raport.md    # raport Markdown (np. do opisu PR)
//   node tools/update-data.mjs --format        # tylko przeformatuj pliki JSON
// Wymaga Node.js 18+ (wbudowany fetch).

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { syncLifecycle, syncKev, formatJson, KEV_URL } from "../assets/datasync.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const file = n => path.join(root, "data", n);
const args = process.argv.slice(2);
const opt = n => { const i = args.indexOf(n); return i >= 0 ? (args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : true) : null; };
const dry = !!opt("--dry-run"), only = opt("--only"), kevFile = opt("--kev-file"), reportFile = opt("--report");
const today = new Date().toISOString().slice(0, 10);

const readJson = async n => JSON.parse(await readFile(file(n), "utf8"));
const fetchJson = async url => {
  const r = await fetch(url, { headers: { "User-Agent": "support-simulator-data-updater" } });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${url}`);
  return r.json();
};

const products = await readJson("products.json");
let lifecycle = await readJson("lifecycle.json");
let vulns = await readJson("vulnerabilities.json");
const report = [`# Aktualizacja danych symulatora — ${today}`, ""];
let changed = false;

if (opt("--format")) {
  for (const [n, o] of [["products.json", products], ["lifecycle.json", lifecycle], ["vulnerabilities.json", vulns]]) await writeFile(file(n), formatJson(o));
  console.log("Przeformatowano pliki w data/.");
  process.exit(0);
}

if (!only || only === "lifecycle") {
  const r = await syncLifecycle(products, lifecycle, fetchJson, today);
  report.push("## Daty wsparcia (endoflife.date)", "");
  if (r.changes.length) {
    report.push("| Produkt | Wersja | Pole | Było | Jest |", "|---|---|---|---|---|");
    r.changes.forEach(c => report.push(`| ${c.name} | ${c.label} | ${c.field} | ${c.from} | ${c.to} |`));
    lifecycle = r.lifecycle; changed = true;
  } else report.push("Bez zmian.");
  if (r.newCycles.length) {
    report.push("", "### Nowe wydania do rozważenia (dodaj ręcznie w data/lifecycle.json)", "");
    r.newCycles.forEach(c => report.push(`- ${c.name}: cykl \`${c.cycle}\`, wydanie ${c.rel}${c.eos ? ", EOS " + c.eos : ""}${c.eol ? ", EOL " + c.eol : ""}`));
  }
  if (r.errors.length) { report.push("", "### Ostrzeżenia", ""); r.errors.forEach(e => report.push("- " + e)); }
  report.push("");
}

if (!only || only === "kev") {
  const kev = kevFile ? JSON.parse(await readFile(kevFile, "utf8")) : await fetchJson(KEV_URL);
  const r = syncKev(products, vulns, kev, today);
  vulns = r.vulnerabilities; changed = true;
  report.push(`## Podatności aktywnie wykorzystywane (CISA KEV ${kev.catalogVersion || ""})`, "", "| Produkt | Wpisy z ostatnich 2 lat | Poprzednio | Najnowszy wpis |", "|---|---|---|---|");
  r.summary.filter(s => s.count2y || s.prev).forEach(s => report.push(`| ${s.name} | ${s.count2y} | ${s.prev} | ${s.latest || "—"} |`));
  report.push("");
}

const text = report.join("\n");
console.log(text);
if (reportFile) await writeFile(path.resolve(reportFile), text + "\n");
if (dry) console.log("\n(--dry-run: pliki nie zostały zapisane)");
else if (changed) {
  await writeFile(file("lifecycle.json"), formatJson(lifecycle));
  await writeFile(file("vulnerabilities.json"), formatJson(vulns));
  console.log("\nZapisano data/lifecycle.json i data/vulnerabilities.json.");
}
