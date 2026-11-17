"""Stage E: OSV and npm advisories of every (name, version) in every resolved production tree."""
import glob, json, sys, urllib.request

W = sys.argv[1]


def post(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)


pairs = set()
for f in glob.glob(f"{W}/trees/*.json"):
    t = json.load(open(f))
    if t["ok"]:
        pairs.update(map(tuple, t["tree"]))
pairs = sorted(pairs)
print("unique (name, version) pairs", len(pairs), file=sys.stderr)

vulnerable = {}  # "name@version" -> advisory ids/urls
for i in range(0, len(pairs), 1000):
    chunk = pairs[i:i + 1000]
    res = post("https://api.osv.dev/v1/querybatch",
               {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]})["results"]
    for (n, v), r in zip(chunk, res):
        ids = [x["id"] for x in r.get("vulns", [])]
        if r.get("next_page_token"):
            ids.append("MORE")
        if ids:
            vulnerable.setdefault(f"{n}@{v}", []).extend(ids)

# npm's bulk endpoint returns an advisory when ANY sent version of a name is affected, so each round sends one version per name
by_name = {}
for n, v in pairs:
    by_name.setdefault(n, []).append(v)
for r in range(max(map(len, by_name.values()))):
    rnd = sorted((n, vs[r]) for n, vs in by_name.items() if r < len(vs))
    for i in range(0, len(rnd), 500):
        adv = post("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", {n: [v] for n, v in rnd[i:i + 500]})
        for n, v in rnd[i:i + 500]:
            for a in adv.get(n, []):
                vulnerable.setdefault(f"{n}@{v}", []).append(a["url"])

json.dump({"pairs": len(pairs), "vulnerable": vulnerable}, open(f"{W}/tree-audit.json", "w"), indent=1)
print("vulnerable pairs (OSV or npm)", len(vulnerable), file=sys.stderr)
