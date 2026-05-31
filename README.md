# 🔭 ArchScope

**Universal CLI for multi-language codebase intelligence** — analyze architecture, security, dependencies and git history across Swift/Objective-C, Kotlin, TypeScript/JavaScript, Python and Go, and produce one interactive HTML report (+ SARIF).

Built in pure Go. One engine, every language: drop a file in `internal/lang/` to add another.

---

## ⚡ Generate Report in 10 Seconds

```bash
cd archscope
go run ./cmd/archscope ~/code --open
```

`~/code` is any directory: a single app, a service repo, or a **parent folder** where several repositories are cloned side by side. Modules/services are auto-detected up to 3 levels deep, so `services/<svc>/`, `src/<module>/` and monorepo layouts all work. `--open` launches the finished report in your browser.

```text
~/code/
├── api-gateway/      ← Go service (.git inside)
├── user-service/     ← Go service
├── ios-app/          ← Swift app
├── android-app/      ← Kotlin app
└── web/              ← TypeScript frontend
```

Each language lands in its own **tab**, ordered by lines of code (largest first). Output is a single self-contained `*.html` file — no external assets, no network. A SARIF 2.1.0 log is also available via `--format sarif` or `--format both`.

---

### What the Report Contains

1. **📊 Summary** — lines of code, files, declarations, modules, the 0–1000 danger index, and platform count, with one tab per language present.

2. **🧰 Tech Stack & Modules** — repo-wide tech-stack cloud (languages + frameworks auto-detected from imports: SwiftUI, Combine, React, Next, Django, FastAPI, net/http, gRPC, GORM, …) and a package grid sized by LOC.

3. **🛡️ Danger Index** — the generalized ArchSwiftScope analyzer: **14 weighted categories summing to 1000 points**, a saturating violation-density curve per category, and bands Hardened / Minor exposure / Elevated risk / Critical exposure. Universal rules (hardcoded secrets, PEM keys, SQL interpolation) plus language-scoped rules for each platform. Findings are attributed to their last author via `git blame`.

4. **Per-platform tabs**, each with:
   - **🏛️ Architecture** — *client* languages (Swift, Objective-C, Kotlin, TS/JS) get **app-architecture pattern detection** (MVC, MVVM and its variants, VIPER, VIP, RIBs, Clean, Redux, TCA, MVP, MV) scored by role conventions. *Backend* languages (Go, Python) get a **goscope-style layered view** — API / Models / Services / Persistence / Auth / Config / CLI / Infra / Tests bars + detected components.
   - **🧩 Design Patterns** — Gang-of-Four detection from declaration-name conventions, grouped Creational / Structural / Behavioral.
   - **⚖️ OOP vs POP** *(Swift)* — places the codebase on the object↔protocol spectrum (Protocol Design 55% · Value Semantics 30% · Anti-inheritance 15%) with a metrics table.
   - **🔧 Microservices** *(Go)* / **📦 Packages & Modules** *(Swift, Kotlin)* — the module grid, labeled per language.
   - **🕸️ Dependency Hotspots** — modules ranked by **Uses** (how many others depend on them), with Lines & Decl; backend tabs also get an inline **dependency graph** (SVG, node size = dependents).
   - **🔎 Security Findings** — this platform's findings grouped by rule, with severity, location and blame author. File locations are **VS Code deep links** (`vscode://`) — click to jump straight to the line.

5. **🐙 Git Analysis** (repo-wide) — top contributors, file churn, semver tags, conventional-commit hygiene, branch inventory with stale detection, and a **branching-model classifier** scoring Gitflow / Trunk-Based / GitHub Flow / GitLab Flow / OneFlow.

6. **📂 Modules & Microservices** — a per-module breakdown at the bottom: each module's project-type badge, declaration mix (🟢 struct · 🔵 class · 🟣 protocol · 🟡 enum · 🔴 actor · 🔹 extension · 🟠 func), and a file inventory (lines, declarations, decl chips) with VS Code links. The per-tab module chips link down to these sections.

---

## 🌐 Languages

Each language is **one self-registering file** in `internal/lang/`. A `LanguageSpec` declares its extensions, detection markers, parse patterns, whether it is a `Client` (UI) language, and its module noun:

| Language | Platform tab | Client? | Module noun |
|----------|--------------|---------|-------------|
| Swift / Objective-C | Swift + ObjC | ✅ | 📦 Packages & Modules |
| Kotlin | Kotlin | ✅ | 📦 Packages & Modules |
| TypeScript / JavaScript | TS + JS | ✅ | 📦 Packages |
| Python | Python | — | 📦 Packages |
| Go | Go | — | 🔧 Microservices |

Adding a language (e.g. `rust.go`) needs no central edit — importing the package triggers its `init()`. The `Client` flag is what routes a tab to pattern detection vs. the layered backend view; the module noun/icon control how its modules are labeled.

---

## 🚀 Quick Start

```bash
# Analyze a local directory and open the report
go run ./cmd/archscope ~/code --open

# Write both HTML and SARIF to ./reports/
go run ./cmd/archscope ~/code --format both --output ./reports

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
| `--format` | `html` \| `sarif` \| `both` | from config (`html`) |
| `--output`, `-o` | output directory | from config (`output/`) |
| `--config` | path to an `.archscope.json` override file | `.archscope.json` |
| `--ref` | git branch/tag/sha to check out (remote URLs only) | default branch |
| `--depth` | shallow-clone depth (remote URLs only; `0` = full history) | `0` |

Outputs are written as `<project-name>.html` and/or `<project-name>.sarif` inside the output directory. Progress is printed per stage:

```text
 → Scanning source tree…
 → Found 24 files across 5 platform(s), 4 module(s)
 → Parsing 24 files…
 → Building dependency graph…
 → Analyzing git history (4 repo(s))…
 → Running 18 security rules…
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

Requires **Go 1.21+**. Module path: `github.com/exey/archscope`. `git` is needed for the git-analysis section and blame attribution (the report degrades gracefully without it).

---

## ⚙️ Configuration

`config.Default()` is the baseline; `config.Load` overlays a user `.archscope.json`, so a partial file only changes the keys it sets (output format/dir, security thresholds and disabled rules, fetch depth, hotspot count).

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
    designpattern/ universal GoF detector
    oopvspop/    Swift-only OOP↔POP analyzer
  result/      AnalysisResult aggregate + pipeline (Run / RunWithProgress)
  report/      shared HTML theme
    html/        HTML writer (tabs, panels, SVG dependency graph, git section)
    sarif/       SARIF 2.1.0 writer
testdata/      go-sample · multi (5-language) · arch-sample (MVVM + patterns)
```

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
| `--format both` | both of the above |

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

## Requirements

- Go 1.21+
- `git` on PATH (optional; only for the git-analysis section and blame attribution)
