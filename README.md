# Symulator cyklu wsparcia składników produktu

Statyczna strona (GitHub Pages), która dla fikcyjnego produktu symuluje okna wsparcia (EOS/EOL), aktualizacje,
podatności, mitygacje, plan modernizacji z darmowymi odpowiednikami i przewidywaną pracochłonność.

## Struktura

| Ścieżka | Zawartość |
|---|---|
| `index.html` | strona (układ) |
| `assets/style.css` | wygląd |
| `assets/app.js` | silnik symulacji i interfejs |
| `assets/datasync.js` | wspólna logika aktualizacji danych (strona i skrypt) |
| `data/products.json` | **produkty**: kategorie, licencje, płatne wsparcie, zmiany niekompatybilne, darmowe odpowiedniki, szablony, mapowania do źródeł |
| `data/lifecycle.json` | **daty wsparcia** każdej wersji (wydanie, EOS, EOL, płatne ESU/ELS) |
| `data/vulnerabilities.json` | **podatności**: założone tempo do symulacji (`rate`) i prawdziwe wpisy z katalogu CISA KEV |
| `tools/update-data.mjs` | skrypt aktualizacji danych |
| `.github/workflows/update-data.yml` | cotygodniowa automatyczna aktualizacja (pull request) |

Strona wczytuje pliki `data/*.json`, więc lokalnie trzeba ją uruchomić przez serwer WWW:

```sh
python3 -m http.server   # następnie http://localhost:8000
```

## Aktualizacja danych

**Automatycznie (zalecane).** Workflow „Aktualizacja danych symulatora” uruchamia się co poniedziałek (lub ręcznie
w zakładce *Actions*) i otwiera pull request z raportem zmian. Wymaga włączenia w ustawieniach repozytorium:
*Settings → Actions → General → Workflow permissions → „Allow GitHub Actions to create and approve pull requests”*.

**Skryptem** (Node.js 18+):

```sh
node tools/update-data.mjs             # endoflife.date + CISA KEV, zapis plików
node tools/update-data.mjs --dry-run   # tylko raport
node tools/update-data.mjs --only lifecycle   # albo: --only kev
node tools/update-data.mjs --format    # przeformatowanie plików po ręcznej edycji
```

Za proxy HTTP(S) uruchom z `NODE_USE_ENV_PROXY=1` (Node 22.21+).

**W przeglądarce.** Sekcja „Dane i ich aktualizacja” na stronie: sprawdzenie dat w endoflife.date na żywo,
zastosowanie zmian lokalnie, pobranie zaktualizowanego `lifecycle.json`, wczytanie własnego pliku danych.
Katalog CISA KEV nie pozwala na pobieranie z przeglądarki — podatności aktualizuje skrypt lub workflow.

**Ręcznie.** Pliki są w czytelnym formacie (jedna wersja w jednej linii):

- nowa wersja produktu — dopisz obiekt w `data/lifecycle.json`, np.
  `{"l":"3.15","rel":"2026-10-09","eos":"2028-10-09","eol":"2031-10-31","cycle":"3.15"}`;
  pole `cycle` wiąże ją z endoflife.date (wtedy skrypt będzie ją aktualizował), `fc: true` oznacza daty prognozowane;
- nowy produkt — dodaj rodzinę w `data/products.json` (`families`), jej wersje w `lifecycle.json` i tempo podatności
  w `vulnerabilities.json`; aby pojawił się w kreatorze, dopisz klucz do `groups` (lub `osCards` dla systemu);
- darmowy odpowiednik — pole `alts` rodziny w `products.json`, np. `{"to":"postgresql","h":600,"notes":[...]}`.

Pola dat w `lifecycle.json`: `eos` — koniec pełnego wsparcia, `eol` — koniec poprawek (darmowych lub
w ramach wsparcia rozszerzonego), `esu` — koniec płatnego wsparcia po EOL. Tryb mapowania z endoflife.date
(`sync.mode` w `products.json`): `default`, `premier` (Oracle) lub `ubuntu` (ESM).

## Informacje prawne

Symulacja ma charakter poglądowy; produkt i podatności o identyfikatorach `SIM-…` są fikcyjne. Sekcja
„Aktualne podatności” pokazuje publiczne dane z katalogu CISA KEV. Daty i informacje licencyjne są przybliżone.
Nazwy produktów są znakami towarowymi ich właścicieli i zostały użyte wyłącznie w celu identyfikacji.
