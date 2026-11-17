"""The role of each listed package by the rules of jelly-taint-benchmarks' SCHEMA.md (`role`), first rule that applies:
extension (engines.vscode), action (action.yml), application (an Electron application, a command-line program:
bin and no main, exports or index.js, a main file that starts a server and exports nothing), mcp (creates a server
of @modelcontextprotocol/sdk), library (an npm package with an API). Tarballs are read in memory, never run.
Writes work/roles.json and the columns role and role_rule of benign-1000.csv."""
import base64, csv, gzip, hashlib, io, json, os, re, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor

EXPORTS = re.compile(r"\bmodule\.exports\b|\bexports\.\w|\bexports\[|^\s*export\s", re.M)
SERVER = re.compile(r"\.listen\s*\(")
ELECTRON = re.compile(r"""require\s*\(\s*['"]electron['"]\s*\)|from\s*['"]electron['"]""")
MCP = re.compile(r"@modelcontextprotocol/sdk")


def leaves(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for v in x.values():
            yield from leaves(v)
    elif isinstance(x, list):
        for v in x:
            yield from leaves(v)


def role(p):
    t = json.load(open(f"{W}/trees/{p['name'].replace('/', '__')}.json"))
    data = urllib.request.urlopen(t["resolved"], timeout=300).read()
    algo, want = t["integrity"].split("-", 1)
    assert base64.b64encode(hashlib.new(algo, data).digest()).decode() == want, "integrity mismatch"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data))) as tar:
        for m in tar:
            if m.isfile():
                files[m.name.split("/", 1)[1] if "/" in m.name else m.name] = tar.extractfile(m).read()
    return p["name"], classify(files)


def classify(files):
    """files: path in the package -> bytes"""
    pj = json.loads(files["package.json"])
    exp = pj.get("exports")
    main_entries = [e for e in [pj.get("main"), *leaves(exp.get(".") if isinstance(exp, dict) and "." in exp else exp)]
                    if isinstance(e, str)]
    def find(e):
        e = os.path.normpath(e[2:] if e.startswith("./") else e)
        return next((c for c in (e, e + ".js", e + ".cjs", e + ".mjs", e + "/index.js") if c in files), None)
    mains = [f for f in dict.fromkeys(map(find, main_entries or ["index.js"])) if f]
    text = {f: files[f].decode("utf-8", "replace") for f in mains}
    all_code = "".join(b.decode("utf-8", "replace") for f, b in files.items() if f.endswith((".js", ".cjs", ".mjs")))
    engines = pj.get("engines")  # an object, or a list of strings in old packages
    if isinstance(engines, dict) and engines.get("vscode") or isinstance(engines, list) and any("vscode" in e for e in engines):
        r, why = "extension", "engines.vscode"
    elif any(f == "action.yml" or f.endswith("/action.yml") for f in files):
        r, why = "action", "action.yml"
    elif any(ELECTRON.search(s) and re.search(r"\bBrowserWindow\b", s) for s in text.values()):
        r, why = "application", "Electron main process"
    elif pj.get("bin") and not (pj.get("main") or exp or "index.js" in files):
        r, why = "application", "bin and no main, exports or index.js"
    elif mains and all(SERVER.search(s) and not EXPORTS.search(s) for s in text.values()):
        r, why = "application", "main file starts a server and exports nothing"
    elif MCP.search(all_code) and re.search(r"\bMcpServer\b|new\s+Server\s*\(", all_code):
        r, why = "mcp", "@modelcontextprotocol/sdk server"
    else:
        r, why = "library", "npm package with an API"
    return {"role": r, "why": why, "main_files": mains, "bin": bool(pj.get("bin"))}


if __name__ == "__main__":
    W, OUT = sys.argv[1], sys.argv[2]  # the work folder, the folder of benign-1000.json and benign-1000.csv
    with ThreadPoolExecutor(4) as ex:
        roles = dict(ex.map(role, json.load(open(f"{OUT}/benign-1000.json"))))
    json.dump(roles, open(f"{W}/roles.json", "w"), indent=1)
    rows = list(csv.reader(open(f"{OUT}/benign-1000.csv")))
    if "role" not in rows[0]:
        for r in rows:
            r += ["role", "role_rule"] if r is rows[0] else ["", ""]
    i, name = rows[0].index("role"), rows[0].index("name")
    for r in rows[1:]:
        r[i], r[i + 1] = roles[r[name]]["role"], roles[r[name]]["why"]
    csv.writer(open(f"{OUT}/benign-1000.csv", "w", newline="")).writerows(rows)
    from collections import Counter
    print(Counter(r["role"] for r in roles.values()))
    for n, r in roles.items():
        if r["role"] != "library":
            print(" ", r["role"], n, "-", r["why"], r["main_files"])
