"""Final selection: every check in candidate order; writes benign/, and work/todo-code.json / work/todo-snyk.json
for candidates still waiting for the tarball check or the Snyk check (Snyk runs only on sink-using survivors)."""
import csv, json, os, shutil, sys
from collections import Counter

W, OUT, N = sys.argv[1], sys.argv[2], 1000
J = lambda f: json.load(open(f"{W}/{f}"))
osv, bench, npm, vul = J("osv-ever.json"), J("benchmark-names.json"), J("npm-ever.json"), J("tree-audit.json")["vulnerable"]
downloads = J("downloads.json")
canon = lambda n: n.replace("/", "__")
STRONG = ("command", "fs", "code", "eval", "Function")


def load(d, n):
    f = f"{W}/{d}/{canon(n)}.json"
    return json.load(open(f)) if os.path.exists(f) else None


reasons, chosen, no_sink, todo_code, todo_snyk = {}, [], [], [], []
for rank, n in enumerate(osv["candidates"], 1):
    t, c, s, m = load("trees", n), load("code", n), load("snyk", n), npm.get(n)
    if osv["osv_ever"][n]:
        why = "OSV advisory (any version): " + " ".join(osv["osv_ever"][n][:5])
    elif n.lower() in bench:
        why = "in SecBench.js/VulcaN/JsVul: " + ",".join(bench[n.lower()])
    elif "error" in m:
        why = "registry metadata not fetched"
    elif m["npm_advisories_ever"]:
        why = "npm advisory (any version)"
    elif t is None:
        why = "dependency tree not resolved yet"
    elif not t["ok"]:
        why = "dependency tree not resolvable before the cutoff"
    elif bad := [f"{a}@{v}" for a, v in t["tree"] if f"{a}@{v}" in vul]:
        why = "vulnerable production dependency: " + " ".join(bad[:5])
    elif t["version"] in m["deprecated"] or m["dist_tags"].get("latest") in m["deprecated"]:
        why = "deprecated"
    elif t["root_install_script"]:
        why = "install script"
    elif n not in downloads:
        why = "weekly downloads not fetched"
    elif downloads[n] < 1000:
        why = "fewer than 1,000 downloads last week (unused or spam)"
    elif c is None:
        todo_code.append(n)
        why = "tarball not checked yet"
    elif "error" in c:
        why = f"tarball not checked ({c['error']})"
    elif c["install_scripts"]:
        why = "install script"
    elif not c["entry"]:
        why = "no JavaScript library entry (CLI-only, types-only or assets-only)"
    elif c["binaries"]:
        why = "ships binaries: " + " ".join(c["binaries"][:3])
    elif c["obfuscation_hex_names"] > 20:
        why = f"obfuscation-like names (_0x...): {c['obfuscation_hex_names']}"
    else:
        p = {"rank": rank, "tier": osv["tier"][n], "weekly_downloads": downloads[n], "name": n, "version": t["version"],
             "tree_size": len(t["tree"]),
             "tree_install_scripts": t["tree_install_scripts"], "entry": c["entry"], "code_files": c["code_files"],
             "code_bytes": c["code_bytes"], "sinks": c["sinks"], "strong_sink": any(k in c["sinks"] for k in STRONG)}
        if not p["sinks"]:
            no_sink.append(p)  # benign by every check except Snyk, which only runs on sink-using packages
            why = "no jelly-taint sink in its own code"
        elif s is None:
            todo_snyk.append(n)
            why = "Snyk not checked yet"
        elif s["status"] != 200:
            why = f"Snyk page not loaded ({s['status']})"
        elif s["ids"]:
            why = "Snyk advisory (any version): " + " ".join(s["ids"][:5])
        else:
            chosen.append(p)
            continue
    reasons[n] = why

json.dump(todo_code, open(f"{W}/todo-code.json", "w"))
json.dump(todo_snyk, open(f"{W}/todo-snyk.json", "w"))
print("candidates", len(osv["candidates"]), "benign with a sink", len(chosen), "benign without a sink", len(no_sink),
      "to code-check", len(todo_code), "to Snyk-check", len(todo_snyk))
for k, v in Counter(r.split(":")[0].split(" (")[0] for r in reasons.values()).most_common():
    print(f"  {v:5} {k}")
if len(chosen) < N or todo_code or todo_snyk[:N - len(chosen)]:
    sys.exit("not final yet")

for p in chosen[N:]:
    reasons[p["name"]] = "passed every check, but comes after the first 1000"
chosen = chosen[:N]
os.makedirs(f"{OUT}/lockfiles", exist_ok=True)
json.dump([{"type": "npm", "name": p["name"], "version": p["version"]} for p in chosen],
          open(f"{OUT}/benign-1000.json", "w"), indent=2)
json.dump(no_sink, open(f"{OUT}/benign-without-sinks.json", "w"), indent=1)
json.dump(reasons, open(f"{OUT}/excluded.json", "w"), indent=1)
with open(f"{OUT}/benign-1000.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["candidate_rank", "popularity_tier", "weekly_downloads", "name", "version", "sinks_in_own_code",
                "strong_sink", "entry", "code_files", "code_bytes", "prod_tree_size", "tree_install_scripts"])
    for p in chosen:
        w.writerow([p["rank"], p["tier"], p["weekly_downloads"], p["name"], p["version"],
                    " ".join(f"{k}:{v}" for k, v in p["sinks"].items()),
                    p["strong_sink"], p["entry"], p["code_files"], p["code_bytes"], p["tree_size"],
                    " ".join(p["tree_install_scripts"])])
for p in chosen:
    d = f"{OUT}/lockfiles/{canon(p['name'])}"
    os.makedirs(d, exist_ok=True)
    for f in ("package.json", "package-lock.json"):
        shutil.copy(f"{W}/lock/{canon(p['name'])}/{f}", d)
print("chosen", len(chosen), "last candidate rank", chosen[-1]["rank"], Counter(p["tier"] for p in chosen),
      "strong sink", sum(p["strong_sink"] for p in chosen))
