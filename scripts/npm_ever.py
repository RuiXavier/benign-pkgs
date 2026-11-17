"""Stage D: npm registry metadata (versions, deprecation, install scripts) and npm's own advisories for EVERY published version."""
import json, os, sys, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

W = sys.argv[1]
osv = json.load(open(f"{W}/osv-ever.json"))
bench = json.load(open(f"{W}/benchmark-names.json"))
names = [n for n in osv["candidates"] if not osv["osv_ever"][n] and n.lower() not in bench]


def meta(name):
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.npm.install-v1+json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                d = json.load(r)
            vs = d.get("versions", {})
            return name, {"dist_tags": d.get("dist-tags", {}), "versions": list(vs),
                          "deprecated": {v: m["deprecated"] for v, m in vs.items() if m.get("deprecated")},
                          "install_script": [v for v, m in vs.items() if m.get("hasInstallScript")]}
        except Exception as e:
            err = repr(e)
    return name, {"error": err}


old = json.load(open(f"{W}/npm-ever.json")) if os.path.exists(f"{W}/npm-ever.json") else {}
with ThreadPoolExecutor(6) as ex:
    metas = dict(ex.map(meta, [n for n in names if n not in old]))
print("metadata errors", sum("error" in m for m in metas.values()), file=sys.stderr)


def bulk(body):
    req = urllib.request.Request("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
                                 json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)


advisories, batch, size = {}, {}, 0
ok = [n for n in metas if "error" not in metas[n]]
for i, n in enumerate(ok):
    batch[n] = metas[n]["versions"]
    size += len(batch[n])
    if size > 5000 or i == len(ok) - 1:
        advisories.update(bulk(batch))
        batch, size = {}, 0
for n in ok:
    metas[n]["npm_advisories_ever"] = [a["url"] for a in advisories.get(n, [])]
metas.update(old)
json.dump(metas, open(f"{W}/npm-ever.json", "w"))
print("checked", len(ok), "with npm advisories ever",
      sum(bool(metas[n]["npm_advisories_ever"]) for n in ok), file=sys.stderr)
