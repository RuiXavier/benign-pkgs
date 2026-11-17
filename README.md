# 1000 benign npm packages for jelly-taint

Made 2026-11-16/17 with the scripts in `scripts/` (see [How it was made](#how-it-was-made)).

These are 1000 popular npm packages with **no known vulnerability anywhere we could look**, whose own code
**uses at least one of jelly-taint's default sinks**. Any warning jelly-taint reports on them is most likely a
false positive.

## Files

| File | What it is |
| --- | --- |
| `benign-1000.json` | The 1000 packages in the pipeline's npm entry format: `{"type": "npm", "name", "version"}` (`NpmTask` in jelly-taint's `benchmarks/tasks/JellyTask.py`). |
| `benign-1000.csv` | The same 1000 with details: popularity tier, last week's downloads, sinks found in the package's own code (number of files per kind), an entry file that exists (the first of `main`, `module`, `exports`, `index.js`), code size, size of the production dependency tree, dependencies with install scripts, role (see [Role and threat model](#role-and-threat-model)). |
| `lockfiles/<name>/` | The audited dependency tree of each package (`package.json` + `package-lock.json` of a small project that depends on it); `/` in a scoped name becomes `__` (`@babel/core` → `@babel__core`). |
| `benign-without-sinks.json` | 3395 more packages that pass every check below except Snyk (not run on them) but whose own code uses no jelly-taint sink. |
| `excluded.json` | Every other candidate with the reason it was dropped. |

## How the packages were picked

**Candidates** (6881): the lists of npm's "high-impact" packages in `npm-high-impact` 1.13.0, without `@types/*`,
in this order:

1. on both lists: at least 1,000,000 downloads a week **and** at least 500 dependent packages (3001),
2. at least 500 dependent packages only (1380),
3. the 2500 most downloaded of those with at least 1,000,000 downloads a week only.

**Checks**, in order. A package is dropped at the first one it fails:

| Check | Dropped |
| --- | ---: |
| An OSV advisory for any version (GitHub advisories and malware reports) | 686 |
| In SecBench.js, VulcaN or JsVul (jelly-taint's `benchmarks/data/*.json`) | 9 |
| npm registry metadata could not be fetched | 3 |
| An npm advisory for any published version (npm's audit database) | 0 |
| Dependency tree could not be resolved with versions from before 2026-10-17 (too new, platform-only builds, spam) | 298 |
| A production dependency (at the resolved version) has an OSV or npm advisory | 1025 |
| The chosen version or the latest version is deprecated | 202 |
| An install script (`preinstall`, `install`, `postinstall`, or `binding.gyp`) | 43 |
| Fewer than 1,000 downloads last week (unused or spam) | 28 |
| Last week's downloads could not be fetched | 1 |
| No JavaScript library entry (`main`, `exports`, `module` or `index.js`): CLI-only, types-only, assets-only | 124 |
| Ships binaries (`.node`, `.wasm`, `.exe`, ...) | 21 |
| Obfuscation-like names (`_0x...`) | 0 |
| No jelly-taint sink in its own code (kept in `benign-without-sinks.json`) | 3395 |
| A Snyk advisory for any version (from its public page, security.snyk.io) | 15 |

1031 packages passed everything; the 1000 first in candidate order are in the list
(529 from tier 1, 176 from tier 2, 295 from tier 3). The other 31 are in `excluded.json` as "passed every check,
but comes after the first 1000".

Details of the checks:

- **Version**: the newest version published before **2026-10-17** (`npm install --before=2026-10-17`), so every
  version in a tree has been public for at least 30 days. A freshly hijacked release would not be picked.
- **Dependency tree**: `npm install --package-lock-only --ignore-scripts --before=2026-10-17 <name>` in an empty
  project: the production dependencies only (not dev dependencies). Every resolved `name@version` (22,712 in all)
  was checked in OSV and in npm's audit database.
- **Code**: the tarball of the chosen version, checked against its lockfile integrity hash, read in memory
  (never unpacked or run). Test, example, fixture and benchmark folders and `.d.ts` files are skipped.
- **Sinks**: a text search for `require`/`import` of `child_process`, `fs`, `fs/promises`, `vm`,
  `worker_threads`, `module` or `repl`, and for `eval(`, `Function(`, and `require(x)`/`import(x)` with a
  non-literal `x`. These are the calls behind jelly-taint's default sink categories (command injection, code
  injection, path traversal, file write). In the CSV, `strong_sink` is false (77 packages) when the only matches
  are `require(x)`/`import(x)` with a variable `x`.
- **Snyk**: Snyk's database has advisories that GitHub's lacks: it flagged 15 packages that OSV and npm show as
  clean, e.g. `bunyan` (remote code execution) and `serve-handler` (information exposure, cross-site scripting).
- **Benchmarks**: SecBench.js and VulcaN cases are matched by npm name; JsVul cases (GitHub repositories) by
  repository name, which is approximate. The final 1000 were also checked against the 689 cases of
  `jelly-taint-benchmarks` (SecBench.js, VulcaN and JsVul, by npm name and repository name): no overlap.
- **Re-check**: on 2026-11-17 the final 1000 were checked again in OSV (any version, and the exact version) and npm
  (the exact version): no advisories.

## Role and threat model

All 1000 are `library` (CSV columns `role` and `role_rule`) by the rules of `role` in jelly-taint-benchmarks'
`SCHEMA.md`, first rule that applies: `extension` (`engines.vscode`), `action` (`action.yml`), `application` (an
Electron application; a command-line program: `bin` and no `main`, `exports` or `index.js`; a main file that
starts a server and exports nothing), `mcp` (creates a server of `@modelcontextprotocol/sdk`), `library` (an npm
package with an API). `scripts/roles.py` applies them; on the 481 npm cases of jelly-taint-benchmarks it gives the
role of their `case.json` for every case (173 `application`, 308 `library`). None of the 1000 is an application
because the selection already requires a library entry file.

The fitting threat model is the library one: the attacker is the caller of the package's API, i.e. jelly-taint's
`--taint-source export`. jelly-taint-benchmarks' `SCHEMA.md` pairs `role: library` with jelly's `--library`, which
is on by default for a package inside `node_modules` (as after installing a lockfile below). The pipeline script
`jelly-taint-with-taint-source-export.json` uses `export` together with every other source category
(`commandargs`, `environment`, `stdin`, `file`, `remote`, `database`, `ipc`) and adds the sinks `xss` and
`open-redirect`.

## Limits

- "Benign" means no **known** vulnerability: a package can still have an unreported one. A jelly-taint warning
  on these packages is most likely, not certainly, a false positive; it still needs a look.
- The sink search is text, not analysis: it shows a package *can* reach a sink, not that untrusted data does.
  A match can also be in a comment or a string.
- Only the package's own code is searched for sinks; a package that reaches `fs` only through a dependency
  (e.g. `fs-extra`) does not count. `inspector`, also a jelly-taint code-injection sink, is not searched.
- Advisories only in other places (a GitHub issue, a CVE without a GitHub or Snyk advisory) are not covered.

## Installing them as audited

jelly-taint's benchmark pipeline (`NpmTask`) unpacks the package and runs a plain `npm install --ignore-scripts`. That installs dev
dependencies too, with whatever versions are newest on the day: not the audited tree.

- Exactly the audited tree: install the saved lockfile, `cd lockfiles/<name> && npm ci --ignore-scripts`; the
  package is then in `node_modules/<name>` (tested: every installed version matches the lockfile).
- Close to it, in the unpacked package: `npm install --omit=dev --ignore-scripts --before=2026-10-17` (same
  dates, but npm does not install the package's own peer dependencies there, so the tree can differ).

## How it was made

Python 3 (standard library only) and npm 11. Every script takes the work folder (`work/`, not in the repository:
about 250 MB of per-package results) as its first argument. Rerunning gives a different list: the databases and
the npm registry change.

```
mkdir -p work untrusted/npm-high-impact
curl -s https://registry.npmjs.org/npm-high-impact/-/npm-high-impact-1.13.0.tgz | tar xz -C untrusted/npm-high-impact
python3 -I scripts/high_impact.py untrusted/npm-high-impact/package work     # candidate lists
python3 -I scripts/benchmark_names.py <jelly-taint>/benchmarks/data work      # SecBench.js, VulcaN, JsVul names
python3 -I scripts/osv_ever.py work                                           # OSV, any version
python3 -I scripts/npm_ever.py work                                           # npm metadata, npm advisories, any version
python3 -I scripts/trees.py work "$PWD/npm-cache" 2026-10-17                 # lockfiles (cache: ~6 GB, absolute path)
python3 -I scripts/tree_audit.py work                                         # OSV + npm for every tree member
python3 -I scripts/downloads.py work                                          # last week's downloads
python3 -I scripts/select.py work .        # stops "not final yet", writes work/todo-code.json
python3 -I scripts/code.py work work/todo-code.json                           # tarball checks
python3 -I scripts/select.py work .        # stops "not final yet", writes work/todo-snyk.json
python3 -I scripts/snyk.py work work/todo-snyk.json                           # Snyk pages, 1 request/s
python3 -I scripts/select.py work .        # writes the files above
python3 -I scripts/roles.py work .                                            # CSV columns role, role_rule
```

The 2026-11-16/17 run took these steps in a slightly different order (the candidate list started with tier 1
only and was extended with tiers 2 and 3 when tier 1 gave too few packages with a sink, and Snyk was also
queried for some packages that failed other checks); the checks are the same.
