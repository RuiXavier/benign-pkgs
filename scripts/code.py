"""Stage F: download each root tarball (version from its quarantined lockfile), verify its integrity, and read it in memory
(never extracted, never run): install scripts, a library entry file, native binaries, obfuscation, and jelly-taint sinks."""
import base64, gzip, hashlib, io, json, os, re, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor

W = sys.argv[1]
names = json.load(open(sys.argv[2]))
os.makedirs(f"{W}/code", exist_ok=True)

MOD = r"""['"](?:node:)?(child_process|fs|fs/promises|vm|worker_threads|module|repl)['"]"""
MODULE_RES = [re.compile(r"\brequire\s*\(\s*" + MOD + r"\s*\)"), re.compile(r"\bfrom\s*" + MOD),
              re.compile(r"\bimport\s*\(\s*" + MOD + r"\s*\)"), re.compile(r"\bimport\s+" + MOD)]
CATEGORY = {"child_process": "command", "fs": "fs", "fs/promises": "fs", "vm": "code", "worker_threads": "code",
            "module": "code", "repl": "code"}
OTHER = {"eval": re.compile(r"(?<![\w$.])eval\s*\("),
         "Function": re.compile(r"\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(\s*['\"`a-zA-Z_$]"),
         "dynamic-require": re.compile(r"(?<![\w$.])require\s*\(\s*(?![\s'\"`)])"),
         "dynamic-import": re.compile(r"(?<![\w$.])import\s*\(\s*(?![\s'\"`)])")}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "example", "examples", "benchmark", "benchmarks",
             "fixtures", "__mocks__", "e2e"}
CODE_EXT = (".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx")
BINARY_EXT = (".node", ".wasm", ".exe", ".dll", ".so", ".dylib")


def leaves(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for v in x.values():
            yield from leaves(v)
    elif isinstance(x, list):
        for v in x:
            yield from leaves(v)


def check(name):
    canon = name.replace("/", "__")
    out = f"{W}/code/{canon}.json"
    if os.path.exists(out):
        return
    t = json.load(open(f"{W}/trees/{canon}.json"))
    res = {"name": name, "version": t["version"]}
    try:
        data = urllib.request.urlopen(t["resolved"], timeout=300).read()
        algo, want = t["integrity"].split("-", 1)
        if base64.b64encode(hashlib.new(algo, data).digest()).decode() != want:
            raise ValueError("integrity mismatch")
        files = {}
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data))) as tar:
            for m in tar:
                if m.isfile():
                    files[m.name.split("/", 1)[1] if "/" in m.name else m.name] = tar.extractfile(m).read()
    except Exception as e:
        res["error"] = repr(e)
        json.dump(res, open(out, "w"))
        return
    pj = json.loads(files.get("package.json", b"{}"))
    scripts = pj.get("scripts") or {}
    res["install_scripts"] = {k: scripts[k] for k in ("preinstall", "install", "postinstall") if k in scripts}
    if "binding.gyp" in files:
        res["install_scripts"]["binding.gyp"] = "node-gyp rebuild"
    entries = [e for e in [pj.get("main"), pj.get("module"), *leaves(pj.get("exports"))] if isinstance(e, str)]
    def exists(e):
        e = os.path.normpath(e.lstrip("./") if e.startswith("./") else e)
        return any(c in files and c.endswith((".js", ".cjs", ".mjs"))
                   for c in (e, e + ".js", e + ".cjs", e + ".mjs", e + "/index.js"))
    res["entry"] = next((e for e in entries if exists(e)), "index.js" if "index.js" in files else None)
    res["binaries"] = sorted(f for f in files if f.endswith(BINARY_EXT))
    code = {f: b for f, b in files.items()
            if f.endswith(CODE_EXT) and not f.endswith((".d.ts", ".d.cts", ".d.mts"))
            and not TEST_DIRS & set(f.split("/")[:-1])}
    res["code_files"], res["code_bytes"] = len(code), sum(map(len, code.values()))
    sinks, obf, longest = {}, 0, 0
    for f, b in code.items():
        s = b.decode("utf-8", "replace")
        for r in MODULE_RES:
            for mod in r.findall(s):
                sinks.setdefault(CATEGORY[mod], set()).add(f)
        for k, r in OTHER.items():
            if r.search(s):
                sinks.setdefault(k, set()).add(f)
        obf += len(re.findall(r"\b_0x[0-9a-f]{4,6}\b", s))
        longest = max([longest, *map(len, s.splitlines() or [""])])
    res["sinks"] = {k: len(v) for k, v in sorted(sinks.items())}
    res["obfuscation_hex_names"], res["longest_line"] = obf, longest
    json.dump(res, open(out, "w"))


done = 0
with ThreadPoolExecutor(4) as ex:
    for _ in ex.map(check, names):
        done += 1
        if done % 200 == 0:
            print(f"{done}/{len(names)}", file=sys.stderr, flush=True)
print("finished", len(names), file=sys.stderr)
