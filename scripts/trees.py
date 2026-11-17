"""Stage B: resolve each clean candidate's production dependency tree with npm, quarantined to --before=CUTOFF.

Writes work/lock/<canon>/package-lock.json and work/trees/<canon>.json (resumable)."""
import json, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

W, CACHE, CUTOFF = sys.argv[1], sys.argv[2], sys.argv[3]
osv = json.load(open(f"{W}/osv-ever.json"))
names = [n for n in osv["candidates"] if not osv["osv_ever"][n]]
os.makedirs(f"{W}/trees", exist_ok=True)


def resolve(name):
    canon = name.replace("/", "__")
    out = f"{W}/trees/{canon}.json"
    if os.path.exists(out):
        return
    d = f"{W}/lock/{canon}"
    os.makedirs(d, exist_ok=True)
    json.dump({"name": "zz-benign-probe-root", "version": "1.0.0", "private": True}, open(f"{d}/package.json", "w"))
    cmd = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
           f"--before={CUTOFF}", "--cache", CACHE, "--loglevel=warn", name]
    res = {"name": name, "legacy_peer_deps": False}
    for extra in ([], ["--legacy-peer-deps"]):
        try:
            p = subprocess.run(cmd + extra, cwd=d, capture_output=True, text=True, timeout=300,
                               env={**os.environ, "CI": "true"})
            ok, err = p.returncode == 0, p.stderr
        except subprocess.TimeoutExpired:
            ok, err = False, "timeout"
        if ok:
            break
        res["legacy_peer_deps"] = True
    res["ok"] = ok
    res["deprecated_warnings"] = [l for l in err.splitlines() if "deprecated" in l]
    if not ok:
        res["error"] = err[-2000:]
    else:
        pk = json.load(open(f"{d}/package-lock.json"))["packages"]
        root = pk.get(f"node_modules/{name}")
        res["version"] = root["version"]
        res["resolved"], res["integrity"] = root.get("resolved"), root.get("integrity")
        res["root_install_script"] = bool(root.get("hasInstallScript"))
        res["tree"] = sorted({(k.rsplit("node_modules/", 1)[1], v["version"]) for k, v in pk.items()
                              if k and "version" in v and not v.get("link")})
        res["tree_install_scripts"] = sorted({k.rsplit("node_modules/", 1)[1] for k, v in pk.items()
                                              if k and v.get("hasInstallScript")})
    json.dump(res, open(out, "w"))


done = 0
with ThreadPoolExecutor(3) as ex:
    for _ in ex.map(resolve, names):
        done += 1
        if done % 100 == 0:
            print(f"{done}/{len(names)}", file=sys.stderr, flush=True)
print("finished", len(names), file=sys.stderr)
