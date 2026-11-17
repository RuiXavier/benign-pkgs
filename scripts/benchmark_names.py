"""The package names of jelly-taint's benchmarks (benchmarks/data/{secbench,vulcan,jsvul,jsvul-pairs}.json) into
work/benchmark-names.json: npm names, and for JsVul (GitHub repositories) also the repository name."""
import json, sys

B, W = sys.argv[1], sys.argv[2]  # jelly-taint's benchmarks/data folder, the work folder
names = {}
for f in ["secbench.json", "vulcan.json", "jsvul.json", "jsvul-pairs.json"]:
    for c in json.load(open(f"{B}/{f}")):
        n = c["package"]["name"].lower()
        names.setdefault(n, set()).add(c["suite"])
        if c["suite"] == "jsvul":
            names.setdefault(n.split("/")[-1], set()).add("jsvul-repo-name")
json.dump({k: sorted(v) for k, v in names.items()}, open(f"{W}/benchmark-names.json", "w"))
