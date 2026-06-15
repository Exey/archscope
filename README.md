# 🏛️🔭 ArchScope

**Universal CLI for multi-language codebase intelligence** — analyze architecture, security, dependencies and git history across Swift/Objective-C, Kotlin, TypeScript/JavaScript, Python, Go and Java, and produce one interactive HTML report, a Markdown document, or a SARIF log.

---

## ⚡ Generate Report in 10 Seconds

```bash
cd archscope
go run ./cmd/archscope ~/code --open
```

`~/code` is any directory: a single app, a service repo, or a **parent folder** where several repositories are cloned side by side. Modules/services are auto-detected up to 3 levels deep, so `services/<svc>/`, `src/<module>/` and monorepo layouts all work. `--open` launches the finished report in your browser. Use `--format md` for a Markdown report, `--format sarif` for SARIF 2.1.0, or `--format both` for HTML + SARIF together.

---

## What the Report Contains

1. **Summary bar** — lines of code, source files, declarations, modules, **Danger rate** (0–100% scaled from the 1000-point index), and platform count. One tab per detected language.

![ArchScope](https://exey.github.io/ArchScopeDocs/as_summary.svg)

2. **🧰 Tech Stack & Modules** — repo-wide tag cloud: languages present + frameworks auto-detected from imports (SwiftUI, Combine, React, Next.js, Django, FastAPI, gRPC, GORM, …) and from config files (docker-compose, go.mod, Makefile). Below it: a package grid sized by LOC with per-language badges. DevOps tools (Docker, Kubernetes, GitHub Actions, etc.) appear when detected.

3. **🛡️ Danger Index** — weighted security score (0 = hardened → 100% = critical) across **14 categories**, each with its own weight and a saturating violation-density curve. Risk band: Hardened / Minor exposure / Elevated risk / Critical exposure. Backed by **137+ security rules** across all languages plus universal cross-language checks.

![ArchScope](https://exey.github.io/ArchScopeDocs/as_danger.svg)

4. **Per-platform tabs** — one tab per language, each containing:

   - **🏛️ Architecture** — *client* languages (Swift/ObjC, Kotlin, TS/JS) get **app-architecture pattern detection**: MVC, MVVM (and variants), VIPER, VIP, RIBs, Clean, Redux, TCA, MVP, MV — scored by role conventions and weighted signals. *Backend* languages (Go, Python, Java) get a **layered architecture view**: API / Models / Services / Persistence / Auth / Config / CLI / Infra / Tests bars + detected component chips.

![ArchScope](https://exey.github.io/ArchScopeDocs/as_platform.svg)

   - **📐 Domain Model** *(Go · Python · Kotlin · Java)* — spectrum from **Anemic Domain Model** (DAO/DTO/Manager-heavy service layer) to **Rich Domain Model** (DDD tactical patterns). Scored across three weighted dimensions:
     - *Rich Domain Types* (40%) — Entities, Value Objects, Aggregates (×2) vs. DAO/DTO/Manager/BO/DO/PO. Detects both **Java/Kotlin-style suffixes** (`*Entity`, `*Repository`) and **Go/Python-style directory conventions** (`aggregate/`, `entity/`, `valueobject/`).
     - *Tactical DDD Patterns* (35%) — Repository, Domain Event, Domain Service, Specification, Use Case, Factory, Event Handler. 5 of 7 = full score.
     - *Layer Separation* (25%) — presence of `/domain/`, `/infrastructure/`, `/application/`, hex-arch port/adapter paths vs. anemic `/dao/` structure. Supports Go monorepo layouts (`/pkg/domain/`, `/internal/domain/`).
     - Verdict: **Strong Rich Domain Model → Leaning DDD → Transitional → Leaning Anemic → Strong Anemic → No Domain Model Detected**.
     - Gradient spectrum bar, per-category bars, metrics table with tooltips and found-type examples.

   - **⚖️ OOP vs POP** *(Swift)* — protocol-oriented vs. object-oriented signal across five categories (Type System, Abstraction, Composition, Behavior, Architecture), with a spectrum bar and per-category breakdown. Appears in place of Domain Model for Swift platforms.

   - **🛜 Traffic** *(Go · Python · Java)* — detected inbound and outbound connection signals: HTTP/gRPC endpoints, listener ports, external service calls, and data formats (JSON, Protobuf, …). Shown as two tables — 📥 Inbound and 📤 Outbound — with URI/pattern, port, protocol, format, and source file.

   - **🛡️ Danger Details** — this platform's rule violations grouped by rule, showing severity, CWE, file location, code snippet, and blame author. File links are **VS Code deep links** (`vscode://`) — click to jump to the exact line.

   - **💡 Module Insights** — four sub-sections in a responsive grid:
     - **🕸️ Dependency Hotspots** — modules ranked by in-degree (how many others depend on them), with Lines & Decl. Backend tabs also include an inline **SVG dependency graph** (node radius ∝ dependents).
     - **🔧 Microservices** *(Go)* / **📦 Packages & Modules** *(other languages)* — clickable module grid with file count and LOC.
     - **🔗 Module Penetration** — modules imported by the most other modules (highest shared-dependency risk).
     - **📝 TODOs & FIXMEs** — per-module TODO and FIXME counts, sorted by total.

   - **📏 Longest Functions** — top 20 non-test functions by line count, with module and VS Code link.

   - **🧩 Design Patterns** *(all languages)* — GoF pattern detection from naming conventions: Factory, Singleton, Builder, Observer, Strategy, Decorator, Adapter, Facade, Command, and more — grouped by Creational / Structural / Behavioral category.

5. **🐙 Git Analysis** (repo-wide):

   - **Branching model classifier** — scores Gitflow / Trunk-Based / GitHub Flow / GitLab Flow / OneFlow with confidence % and detected signals.
   - **Top contributors** — commits and files touched per author.
   - **File churn** — most-modified files across history.
   - **Tags & commits** — semver tag list, commit volume, conventional-commit hygiene.
   - **Branch inventory** — all branches with stale detection.

6. **📂 Modules & Microservices** — per-module deep-dive at the bottom of the report: project-type badge, declaration mix, and a full file inventory (lines, declarations, decl chips) with VS Code deep links. Module chips in each platform tab link down here.

---

## 🌐 Languages

Each language is **one self-registering file** in `internal/lang/`. A `LanguageSpec` declares its extensions, detection markers, parse patterns, whether it is a `Client` (UI) language, and its module noun:

| Language | Security | UI scan |
| --- | --- | --- | 
| Go | ✅ language rules + universal | — | 
| Python | ✅ language rules + universal | — | 
| Java | ✅ language rules + universal | — |
| TypeScript / JavaScript | ✅ language rules + universal | ✅ |
| Kotlin | ✅ language rules + universal | ✅ |
| Swift / Objective-C | ✅ language rules + universal | ✅ |

Adding a language (e.g. `rust.go`) needs no central edit — importing the package triggers its `init()`. The `Client` flag is what routes a tab to pattern detection vs. the layered backend view; the module noun/icon control how its modules are labeled.

Drop a file in `internal/lang/` to add another.

---

## 🚀 Quick Start

```bash
# Analyze a local directory and open the report
go run ./cmd/archscope ~/code --open

# Write both HTML and SARIF to ./reports/
go run ./cmd/archscope ~/code --format both --output ./reports

# Write a Markdown report (no CSS/JS — ideal for wikis, CI artefacts, LLM input)
go run ./cmd/archscope ~/code --format md --output ./reports

# Monorepo: show each top-level folder as its own tab / section
go run ./cmd/archscope ~/code --folder-as-tab --open

# Monorepo: Markdown report with one section per folder
go run ./cmd/archscope ~/code --folder-as-tab --format md --output ./reports

# Analyze a remote repository (cloned to a temp dir; full history for git insights)
go run ./cmd/archscope https://github.com/owner/repo --open

# Pin a specific branch or tag when analyzing a remote repo
go run ./cmd/archscope https://github.com/owner/repo --ref main --open

# Build a binary
go build -o archscope ./cmd/archscope
./archscope ~/code --open
```

### Flags

| Flag | Meaning | Default |
|------|---------|---------|
| `--open` | open the HTML report in the browser when done | off |
| `--format` | `html` \| `sarif` \| `md` \| `both` | from config (`html`) |
| `--output`, `-o` | output directory | from config (`output/`) |
| `--config` | path to an `.archscope.json` override file | `.archscope.json` |
| `--ref` | git branch/tag/sha to check out (remote URLs only) | default branch |
| `--depth` | shallow-clone depth (remote URLs only; `0` = full history) | `0` |
| `--folder-as-tab` | monorepo mode: show each top-level folder as its own tab/section | off |

Outputs are written as `<project-name>.html`, `<project-name>.md`, and/or `<project-name>.sarif` inside the output directory.

#### `--folder-as-tab`

In a monorepo where several services share a language, all Go files would otherwise land in one tab. `--folder-as-tab` splits them by top-level folder, producing tabs like **pharmzakaz Py**, **pharmen Go**, **gptzakaz TS**. Short language labels are used: `Go`, `Py`, `TS`, `Kt`, `Swift`. Tabs for the same folder are kept visually adjacent with a separator. Module names in the dependency graph are folder-qualified (`backend(pharmen)` vs `backend(pharmzakaz)`) so they remain unambiguous across tabs. The Markdown report mirrors this — each folder+language combination becomes its own `##` section. Progress is printed per stage:

```text
 → Scanning source tree…
 → Found 24 files across 5 platform(s), 4 module(s)
 → Parsing 24 files…
 → Building dependency graph…
 → Analyzing git history (4 repo(s))…
 → Running 96 security rules…
 → Attributing findings via git blame…
 → Running report modules…
HTML  → output/myproject.html
```

---

## 🏗️ Build & Install

```bash
go run ./cmd/archscope ~/code --open     # 1) try it instantly
go build -o archscope ./cmd/archscope    # 2) build a binary
go install ./cmd/archscope               # 3) install system-wide ($GOBIN)
```
---

## ⚙️ Configuration

`config.Default()` is the baseline; `config.Load` overlays a user `.archscope.json`, so a partial file only changes the keys it sets (output format/dir, security thresholds and disabled rules, fetch depth, hotspot count).

---

## 🔐 SARIF & CI/CD Integration

ArchScope can emit a **SARIF 2.1.0** log alongside (or instead of) the HTML report. SARIF is the standard format consumed by GitHub Code Scanning, GitLab SAST, VS Code's SARIF Viewer extension, and most security dashboards.

### GitHub Actions

```yaml
- name: Run ArchScope
  run: |
    go run ./cmd/archscope . --format both --output reports

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/${{ github.event.repository.name }}.sarif
  if: always()
```

Findings appear inline on pull requests under the **Security → Code scanning** tab.

### GitLab CI

```yaml
archscope:
  stage: test
  script:
    - go run ./cmd/archscope . --format sarif --output gl-reports
  artifacts:
    reports:
      sast: gl-reports/*.sarif
    paths:
      - gl-reports/
    when: always
```

### VS Code SARIF Viewer

1. Install the [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) extension.
2. Run `archscope . --format sarif`.
3. Open `output/<project>.sarif` — findings appear in the Problems panel with file links.

### Output files

| Flag | Files written |
| --- | --- |
| `--format html` | `<output>/<project>.html` |
| `--format sarif` | `<output>/<project>.sarif` |
| `--format md` | `<output>/<project>.md` |
| `--format both` | `<output>/<project>.html` + `<output>/<project>.sarif` |

The SARIF log maps each security rule to a `reportingDescriptor`, each finding to a `result` with `physicalLocation` (file + line), and severity to SARIF levels (`error` = HIGH, `warning` = MEDIUM, `note` = LOW).

---

## 🧪 Testing

```bash
go test ./...                 # all tests
go vet ./...                  # vet
gofmt -l .                    # formatting (should print nothing)
go test ./internal/git/...    # one package
```

---

## 📁 Project Structure

```
cmd/archscope/main.go        CLI entry point — flags, progress, --open, --format, remote URL support
internal/
  config/      global config + user-override overlay
  langspec/    LanguageSpec, Platform, Registry (Client / ModuleNoun helpers)
  lang/        one file per language (+ *_security.go rule files)
  parser/      universal model + line scanner + dispatch
  scanner/     tree walk, module detection, platform bucketing
  security/    engine, 14 categories, model, helpers
    universal/   cross-language rules (secrets, private keys, SQLi)
  graph/       module dependency graph + PageRank + edges
  git/         history, blame, branching-model classifier
  fetch/       remote git-URL resolution (clone + cleanup)
  modules/     pluggable report modules
    arch/        architecture: client pattern detection + backend layered view
    dddmodel/    DDD vs. Anemic Domain Model analyzer (Go · Python · Kotlin · Java)
    designpattern/ universal GoF detector
    oopvspop/    Swift-only OOP↔POP analyzer
  result/      AnalysisResult aggregate + pipeline (Run / RunWithProgress)
  report/      shared HTML theme
    html/        HTML writer (tabs, panels, SVG dependency graph, git section)
    sarif/       SARIF 2.1.0 writer
    markdown/    Markdown writer (mirrors HTML content; no CSS/JS)
testdata/      go-sample · multi (5-language) · arch-sample (MVVM + patterns)
```

---

## Requirements

- Go 1.21+
- `git` on PATH (optional; only for the git-analysis section and blame attribution)
