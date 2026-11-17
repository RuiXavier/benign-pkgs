"""Last-week download counts from npm's downloads API (bulk for unscoped names, one call per scoped name),
for the candidates without an OSV advisory whose dependency tree resolved."""
import json, os, sys, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

W = sys.argv[1]
osv = json.load(open(f"{W}/osv-ever.json"))
tree = lambda n: f"{W}/trees/{n.replace('/', '__')}.json"
names = [n for n in osv["candidates"]
         if not osv["osv_ever"][n] and os.path.exists(tree(n)) and json.load(open(tree(n)))["ok"]]
out = f"{W}/downloads.json"
counts = json.load(open(out)) if os.path.exists(out) else {}
names = [n for n in dict.fromkeys(names) if n not in counts]


def get(path):
    for attempt in range(5):
        try:
            with urllib.request.urlopen("https://api.npmjs.org/downloads/point/last-week/" + path, timeout=60) as r:
                return json.load(r)
        except Exception as e:
            err = e
            time.sleep(5 * (attempt + 1))
    print("failed", path, err, file=sys.stderr)
    return None


unscoped = [n for n in names if not n.startswith("@")]
for i in range(0, len(unscoped), 128):
    d = get(",".join(unscoped[i:i + 128])) or {}
    for n in unscoped[i:i + 128]:
        if d.get(n):
            counts[n] = d[n]["downloads"]


def scoped(n):
    d = get(urllib.parse.quote(n, safe="@"))
    return n, d and d.get("downloads")


with ThreadPoolExecutor(3) as ex:
    for n, c in ex.map(scoped, [n for n in names if n.startswith("@")]):
        if c is not None:
            counts[n] = c
json.dump(counts, open(out, "w"))
print("counts", len(counts), "missing", sum(n not in counts for n in names), file=sys.stderr)
